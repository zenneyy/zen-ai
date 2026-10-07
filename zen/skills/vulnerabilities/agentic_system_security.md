---
name: agentic-system-security
description: Security testing for authorized AI agents and MCP-style tool ecosystems — effective authority, tool/resource/prompt inventory, confused-deputy behavior, side-effect authorization, cross-tenant isolation, executable component supply chain, memory-tool sandbox integrity, and cross-agent trust
---

# Agentic System Security

Use this skill when an AI system can select tools, retrieve resources, invoke remote/local services, maintain memory, delegate to other agents, or install skills/plugins. Pair it with `llm_prompt_injection` for instruction attacks and classic vulnerability skills for the downstream HTTP, cloud, filesystem, identity, or code-execution sink.

Prompt text is not an authorization boundary. Treat the agent runtime as a confused deputy whose effective authority is bounded by the union of its credentials, tools, resources, network reach, filesystem access, delegated agents, and approval policy, then reduce that upper bound to the actually reachable subset by tracing token audience, scopes, routing, target authorization, environment, and approval flow.

## Standards Mapping

Agentic security has two authoritative sources as of this writing:

- **OWASP Top 10 for LLM Applications 2025** places prompt injection and excessive agency as the primary agentic risks. **LLM01:2025 Prompt Injection** is the top risk for the second consecutive edition and covers both direct instructions and indirect injection (via retrieved content, documents, tool metadata). **LLM06:2025 Excessive Agency** is the entry that directly addresses agent systems and codifies three root causes: excessive functionality, excessive permissions, excessive autonomy. Both are load-bearing for a 2024–2026 agentic security review.
- **Model Context Protocol (MCP) specification** at modelcontextprotocol.io defines the trust model, authorization expectations, and security best practices for MCP servers. The spec is the authority on what a correctly-configured MCP server does — treat deviations as findings.

Supporting references: Anthropic MCP security docs; OpenAI Agents SDK docs; Google A2A (Agent-to-Agent) protocol spec. Treat vendor security blogs (Simon Willison, Anthropic engineering blog) as primary analysis sources — they document the current state of tool-metadata-injection and agent-sandbox research faster than any academic venue.

## Effective-Authority Map

Draw the complete path:

```text
user / external content
  -> model context and memory
  -> planner / router / policy
  -> tool or delegated agent
  -> credential and target system
  -> side effect / returned data
```

Inventory, for each node:

- trust source and tenant/user ownership
- immutable component identity, package/server name, version, and transport
- tools, resources, prompts, model endpoints, plugins, skills, and MCP servers
- credential identity, issuer, audience/resource, subject, tenant, scopes/roles, expiry, downstream token exchange, environment, and where it is injected
- readable data and write/execute capabilities
- network/listener exposure and test-versus-production target
- argument validation, authorization point, approval point, schema/argument digest, delegated principal propagation, and audit log
- data returned to the model and whether it can contain new instructions

Test from the lowest-privileged realistic user and device. The key comparison is the user's authority versus the agent/tool credential's authority.

## Core Test Areas

### Shadow Agent and AI Discovery

Do not assume the approved application inventory contains every agent, model endpoint, browser extension, local MCP server, or AI API integration. Correlate multiple independent signals:

- DNS/proxy/egress logs for first-seen model, agent, vector database, plugin, and AI SaaS domains
- OAuth/SSO grants, enterprise-app consent, service principals, API tokens, and unusual delegated scopes
- endpoint processes, browser extensions/native messaging, listening loopback ports, and MCP client/server configuration
- repository, CI/CD, secrets-manager, and container/image references to model providers, tool servers, and AI credentials
- cloud-hosted model endpoints, notebooks, functions, gateways, and procurement/expense/SaaS inventory

Baseline local discovery from the host before interpreting network or SSO signals:

```bash
# macOS
lsof -nP -iTCP -sTCP:LISTEN
ps -axo pid,ppid,user,command

# Linux
ss -lntp
ps -eo pid,ppid,user,args

# Windows PowerShell
Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess
Get-Process | Select-Object Id,ProcessName,Path

# Cross-platform config and credential leads
rg -l 'mcpServers|modelContextProtocol|OPENAI_API_KEY|ANTHROPIC_API_KEY|AZURE_OPENAI_ENDPOINT' <reviewed-roots>
```

Correlate each listener or config hit to PID/container, parent process, binary hash/version, launch command, config file, destination, and credential reference before calling it an active agent component. A loopback listener is a lead, not proof of reachable authority.

Classify each discovered integration by data read, data write, external communication, execution, identity/admin, and production reach. Human-validate attribution before treating a domain or key name as active AI use. Inspect unauthenticated local MCP/agent listeners separately; network inventory tools often miss loopback-only services.

### Tool Discovery and Argument Boundaries

- Enumerate advertised and conditionally available tools, resources, prompts, schemas, annotations, and delegated agents.
- Compare what the UI exposes with what the protocol/runtime accepts directly.
- Test missing, extra, duplicate, nested, oversized, alternate-type, and cross-tenant identifiers in tool arguments.
- Validate scheme/host/path, filesystem paths, cloud resource IDs, recipient identities, SQL/query fields, and command arguments at the tool boundary.
- Treat tool descriptions, names, examples, resource metadata, and returned content as attacker-influenceable unless provenance is enforced.
- Canonicalize tool identity as `server identity/version + endpoint/transport + tool name + schema digest`; do not collapse two identically named tools from different servers into one trust decision.
- Treat protocol hints such as `readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint` as untrusted metadata, not authorization.
- Verify that unknown tools or schema-invalid calls fail closed without falling back to a broader handler.

### Confused Deputy and Consequential Actions

- Ask whether untrusted user/document/tool text can choose the tool, target, identity, or action.
- Test read-to-write escalation: a summarizer should not send, publish, delete, purchase, deploy, or modify because retrieved text requests it.
- Test whether approval binds the exact server identity/version, tool name, schema digest, normalized arguments, credential, target, side effect, and expiry. Revalidate those fields immediately before execution; a generic "continue?" is weak if arguments can change after approval.
- Exercise replay, retry, parallel calls, partial failure, cancellation, and delegated execution for duplicate or bypassed actions.
- Prove impact at the actual target and audit log. Model narration or a fabricated tool result is not evidence.
- Use dry-run/no-op/read-only operations first; require explicit human approval for consequential operations.

### Identity, Tenant, and Environment Isolation

- Vary user, workspace, tenant, session, conversation, and delegated-agent identity independently.
- Test whether one tenant can reference another tenant's resources, tool sessions, caches, vector entries, files, or credentials.
- Check whether development/test tools or credentials can reach production, and whether local tools inherit broad workstation authority.
- Verify credential scoping at the target service, not only in the agent's application logic.
- Confirm memory and cached tool results are partitioned and revoked when identity or role changes.
- **Stateless-deployment instance reuse**: in a stateless HTTP MCP deployment, verify that a single server/transport instance is not reused across clients — a verified 2026 advisory (named by number in `agentic_system_security_novel_deep`) demonstrated cross-client data leak via shared instance reuse.

### MCP and Local Tool Servers

- Inventory stdio, streamable HTTP, SSE/legacy, and custom transports; record bind address, origin/auth controls, process command, environment, and lifecycle.
- Look for unauthenticated loopback services reachable from browsers, containers, local users, SSRF, port forwarding, or shared hosts.
- Compare `tools/list`, `resources/list`, and `prompts/list` results across identities, but do not assume listing means calling is authorized.
- For each tool, validate the same authorization and argument checks through every supported transport.
- Treat server-launched subprocess configuration, environment variables, and working directories as sensitive executable configuration.
- For HTTP/SSE transports, validate OAuth issuer, signature, expiry, audience/resource, tenant, and scope claims at the server boundary. Reject tokens minted for the wrong audience, and do not treat a session ID as identity.
- For downstream APIs, do not pass through the same bearer token unless the target explicitly authorizes that audience and principal. Separate upstream MCP authentication from downstream target authorization.
- For browser or loopback OAuth, review redirect URI, state/PKCE handling, localhost binding, and consent proxying. Treat metadata fetches and tool discovery on remote servers as SSRF-relevant surfaces.
- For stdio servers, the launch command and environment are already code execution. Discovery must not execute an unreviewed server binary or mutable package tag.
- **DNS rebinding on local HTTP MCP**: a loopback-bound MCP HTTP server without DNS rebinding protection is reachable from a browser on the user's machine — a 2025 advisory documents this against the MCP TypeScript SDK before 1.24.0 (details in `agentic_system_security_novel_deep`).

### Executable Component Supply Chain

Every skill, plugin, MCP server, model adapter, package, and update channel is an executable or behavior-shaping dependency. Record:

- canonical source, publisher, package namespace, pinned version and integrity/provenance
- install/update mechanism, manifest/lockfile/config source, mutable tags, automatic updates, and rollback path
- declared and effective permissions, credentials, filesystem/network access
- transitive dependencies and lifecycle scripts
- review/approval ownership and last verification date

In agent and MCP configs, inspect `command: npx` with `-y` and a bare package or
binary name. The process can fetch code without an interactive prompt and then
run it with the agent's authority. Load `npx_confusion` to determine whether the
name resolves locally, becomes a public package spec, and belongs to the
intended publisher.

Test missing/private-name fallback, typosquatting exposure, mutable remote instructions, compromised-update blast radius, and whether an "instruction-only" component can invoke tools or modify executable files. Resolve `latest`, floating git refs, and mutable image tags to immutable versions or digests before launch. Do not claim or publish contestable package names as proof, and do not execute unknown packages just to discover what they are.

Load `infrastructure_lifecycle` when a skill, plugin, MCP server, model adapter, tool-schema origin, package namespace, or update endpoint is retired, mutable, or externally reassignable. Passive receipt of an agent heartbeat or catalog request does not authorize returning tool definitions, prompts, commands, or executable content.

### Memory-Tool Sandbox Integrity

Agent frameworks that give the model a persistent memory tool (filesystem-backed, vector-store-backed, or key-value-backed) must ensure the memory tool is sandboxed and that each operation re-validates its target. The 2026 Claude SDK Python advisory established a measured TOCTOU pattern:

- the async memory tool validated that a model-supplied path resolved inside the sandbox,
- then returned the *unresolved* path for subsequent operations,
- so a local attacker who could write to the memory directory could retarget a symlink between validation and use, escaping the sandbox on read/write.

Testing memory tools:

- Enumerate the memory-tool implementation: synchronous or asynchronous? Path-resolution timing?
- Test TOCTOU: validate path T, swap symlink T→elsewhere, use T → where does the operation land?
- Test default file permissions: are memory files world-readable? Group-readable? A world-readable memory directory is a `information_disclosure` primitive.
- Test cross-session persistence: does memory from session A leak to session B? If memory is a user-scoped tool, this is a cross-user data leak.
- Test memory-content injection: if memory can contain tool-call-shaped content, does it influence the next conversation's tool selection? This is the "poisoned memory" primitive.

### Output, Telemetry, and Failure Modes

- Validate model/tool output before it reaches HTML, shell, SQL, URLs, file paths, templates, or a second agent.
- Ensure logs record initiating user, tool/server identity, sanitized arguments, approval, target, result, and correlation ID without storing secrets.
- Test timeout, tool error, truncated output, malformed result, model retry, and policy-service failure. Failures should not silently switch to a more privileged tool or credential.
- Verify kill switches, credential revocation, and disabling a component actually terminate active sessions and queued work.

## Primitive Classes

Agentic security has a small set of recurring primitive classes. Each is a template for a finding:

### Tool-Metadata Prompt Injection

**Class**: tool descriptions, resource metadata, prompt templates, or returned tool content contain attacker-controlled instructions that the model treats as directive.

**Instances**: README of a repository the agent reads; filename of a document the agent summarizes; description of a tool in a dynamically-added MCP server; a resource's title field.

**Finding template**: `<path>` contains `<injection>` → agent `<performed privileged action>`.

### Tool Poisoning / Rug-Pull

**Class**: a tool's behavior at approval time differs from its behavior at execution time, because the server mutated the tool definition or the backend behavior.

**Instances**: an MCP server whose tool description changes after the client caches it; a tool whose schema is approved but whose implementation calls a different endpoint; a tool with pinned-version drift (package tag `latest` resolves to a different version at next launch).

**Finding template**: approve `tool(X)` for `safe_scope`; next execution of `tool(X)` performs `unsafe_scope`.

### Cross-Client Instance Reuse

**Class**: a stateless deployment reuses server or transport instances across clients, leaking data or allowing cross-client action.

**Instances**: a Node.js MCP HTTP server with a single `McpServer` instance; a transport object reused across requests; a database connection shared without per-request scoping.

**Finding template**: client A's data visible in client B's session.

### DNS Rebinding to Loopback MCP

**Class**: a loopback-bound MCP server without origin/host validation is reachable from a browser via DNS rebinding.

**Instances**: `localhost:5000/mcp` without `enableDnsRebindingProtection`; a dev-mode HTTP MCP server with permissive CORS.

**Finding template**: attacker's web page triggers tool invocation on the user's localhost MCP.

### Token Pass-Through to Downstream

**Class**: the MCP server receives a user's OAuth token and passes it to a downstream API without re-scoping or validating audience.

**Instances**: an MCP tool that calls Google Drive with the user's Google OAuth; a tool that calls GitHub with the user's GitHub token; any tool that trusts upstream auth as sufficient for downstream.

**Finding template**: a tool with narrower intended scope executes against a resource beyond that scope because the token's audience permits it.

### Memory TOCTOU Sandbox Escape

**Class**: a memory tool validates a path once, then reuses the pre-validation reference for subsequent I/O, allowing a swap between validation and use.

**Instances**: the Claude SDK Python async memory tool case (verified 2026 CVE); any similar async or deferred filesystem operation.

**Finding template**: validate path T, swap T→elsewhere, next I/O lands outside the sandbox.

### Agent-Driven Business Flow Abuse

**Class**: an agent operating at machine speed executes a business flow at a rate or scale that violates business invariants.

**Instances**: an agent making purchases on behalf of a user at bot-speed; an agent making a sequence of actions that collectively violate a per-user limit the per-request handler doesn't see.

**Finding template**: agent completes N actions in T seconds that a human-paced user could not; the business invariant (`API6:2023 Unrestricted Access to Sensitive Business Flows`) is violated. Load `business_logic`.

### Delegated-Agent Authority Expansion

**Class**: Agent A delegates to Agent B, but B operates with A's credentials (not scoped-down), and B's actions appear in B's audit log as B's actions.

**Instances**: a planner agent that delegates filesystem writes to a sub-agent; a chat agent that delegates to a tool-use agent.

**Finding template**: Agent B performed `<action>` with Agent A's credential; audit log attributes to B; principal invariant broken.

## Agent-to-Agent (A2A) and Multi-Agent Architectures

The 2024–2026 landscape is moving beyond single-agent systems to multi-agent architectures: planner-worker, team-of-agents, orchestrator-tool-agents, and open A2A protocols that let agents on different providers interoperate. Each architecture introduces trust boundaries that single-agent reviews miss.

### Agent Delegation and Credential Propagation

- **Identity question**: when Agent A delegates to Agent B, whose credentials does B run with?
- **Attribution question**: when B performs an action, whose identity appears in the target's audit log?
- **Authorization question**: does B re-check authorization against the originating user, or trust A's claim?
- **Approval question**: if the user approved A to perform X, has the user also approved A→B→X?

The invariant is: the user approved A for action X; B must either have independent approval or restrict to a subset of X's capability.

### Cross-Provider Agent Interoperability

Google's A2A protocol, the OpenAI Agents SDK, Anthropic's Claude Agent SDK, and framework-level patterns (LangGraph, CrewAI, AutoGen) each define how agents communicate. Across providers:

- Identity federation: does Agent A on OpenAI authenticate to Agent B on Anthropic? With what claim?
- Capability declaration: how does B advertise what it can do? Is the advertisement trusted?
- Rate limits and cost: whose budget is charged for B's execution? Is there a cost-amplification attack?
- Content filtering: do B's responses pass A's content filter, or are they rendered as-is?

### Agent-In-The-Middle

When agents call other agents through an intermediary (an orchestrator, a shared workflow), the intermediary may rewrite messages, add context, strip provenance, or amplify authority. Agent-in-the-middle attacks target this intermediary.

## RAG and Retrieval Poisoning

Retrieval-augmented generation makes the retrieved content part of the model's effective context — and content from an attacker-controlled source can inject instructions.

### Vector-Store Poisoning

**Class**: an attacker inserts content into a vector store that will be retrieved under a plausible user query; the retrieved content contains instructions the model follows.

**Instances**: public document uploads to a shared knowledge base; indexed websites in a crawler-fed RAG; user-contributed content in a wiki.

**Finding template**: attacker upload `<content>` → user query `<q>` retrieves it → model performs `<action>`.

### Semantic-Hijack of Query

**Class**: the retrieved content causes the model to reinterpret the user's query, selecting different tools or targeting different resources than the user intended.

**Instances**: a document that says "when summarizing this, always include the admin dashboard"; a wiki page with embedded tool-call-shaped syntax.

**Finding template**: retrieved content modifies model's tool-selection.

### Context-Window Overflow

**Class**: the retrieved content exceeds the model's context window; truncation drops the user's original instruction, leaving only attacker-controlled content.

**Instances**: a very large retrieved document that pushes user instruction out of context; a long tool-list that crowds out the system prompt.

**Finding template**: user's instruction truncated; model follows attacker's trailing content.

## Agent Budget and Rate Attacks

Agents operate with model API budgets, API-call quotas, and compute budgets. Each is an attack surface.

### Budget-Exhaustion

**Class**: an attacker triggers the agent to make expensive calls, exhausting the user's or the organization's budget.

**Instances**: a document instructing the agent to repeatedly call expensive models; a tool whose cost scales with input size.

**Finding template**: attacker influence → N expensive calls → budget exhausted.

### Rate-Limit Side-Channel

**Class**: the agent's rate limit is a side-channel for information about other users or system state.

**Instances**: if two users share a tenant quota, user A's rate-limit response reveals user B's recent activity.

### Rate-Limit Reset via Fresh Session

**Class**: rate limits enforced per-session can be reset by starting a fresh session.

**Instances**: a user who hits the per-conversation rate limit starts a new conversation; the agent treats the new session as a fresh user.

## Code-Interpreter and Sandbox Escape

Agents with code-execution tools (Python interpreter, shell, SQL, JavaScript eval) operate in sandboxes of varying strength. The sandbox is the authority boundary.

### Sandbox Classes

- **Process-level**: a subprocess with capped CPU/memory/time; no filesystem isolation.
- **Container-level**: Docker/Podman with namespace isolation; filesystem/network scoped.
- **MicroVM**: Firecracker, gVisor; stronger kernel isolation.
- **WASM**: in-process sandbox; limited I/O.
- **No sandbox**: direct execution in the agent's process — any `rce` primitive is immediate full access.

### Primitive Class: Sandbox-Escape via Shared Filesystem

**Class**: the sandbox allows writes to a shared directory with the host; the agent writes to a path that affects host behavior (e.g., a `.bashrc`, an `authorized_keys`, a crontab).

**Instances**: a Jupyter kernel in a container that shares `/workspace` with the host; a Python interpreter that can write to `/tmp` on host.

**Finding template**: agent writes `<file>` → host executes `<file>` on next event → sandbox escape.

### Primitive Class: Sandbox-Escape via Package Installation

**Class**: the sandbox allows `pip install` or `npm install`; the installed package's install script executes.

**Instances**: a Python sandbox that permits network and `pip install`; attacker-authored package with malicious `setup.py`.

**Finding template**: agent instructed to `pip install evil-pkg` → setup.py runs → sandbox escape.

### Primitive Class: Memory-Tool Sandbox Escape (TOCTOU)

As documented in the base — the 2026 Claude SDK Python CVE establishes this class. See the Memory-Tool Sandbox Integrity subsection above and `agentic_system_security_novel_deep` for the full CVE treatment.

## Safe Testing Workflow

1. **Map** every capability and trust boundary before injecting prompts.
2. **Classify** tools as read, write, execute, communicate, identity/admin, or external-cost.
3. **Establish controls** with dedicated test tenants, synthetic data, read-only credentials, budgets, and target allowlists.
4. **Probe one boundary** at a time: selection, arguments, authorization, approval, execution, result handling.
5. **Validate the side effect** in the target system and audit trail; compare denied and allowed identities.
6. **Chain confirmed primitives** using the effective-authority and capability map from this skill.
7. **Clean up and revoke** created data, sessions, tokens, and local servers.
8. **Turn each confirmed case into a regression** across relevant models, prompts, tools, roles, and environments.

## MCP Inspector (Conditional)

Use the official [MCP Inspector](https://github.com/modelcontextprotocol/inspector) only against a reviewed local/test server:

```bash
npx @modelcontextprotocol/inspector@<reviewed-version> --cli \
  --config reviewed-mcp.json --server test-server \
  --method tools/list --format json
```

- Current upstream requirements should be checked before pinning; as of August 12, 2026, MCP Inspector 2.1.0 requires Node.js `>=22.19.0`.
- Prefer CLI/TUI and loopback binding over exposing the web UI.
- Preserve the generated API token; never disable authentication or bind the process-spawning backend to an external interface.
- Do not publish ports 6274/6277 or pass through the Docker socket/host devices.
- `tools/list` is protocol-read-only, but launching/initializing an arbitrary stdio server executes it and list handlers can still have process-side effects. Review the server command/config first. Calling a tool can perform real external actions.
- Treat the inspected server command/config as executable; `npx` also downloads code, so pin a reviewed package version for repeatable or sensitive work.

## Regression With Promptfoo (Conditional)

[Promptfoo](https://github.com/promptfoo/promptfoo) can encode a bounded model/tool safety matrix after manual validation:

```bash
npx promptfoo@<reviewed-version> eval
```

- Current upstream engine constraints should be checked before pinning; as of August 12, 2026, Promptfoo documents Node.js `^20.20.0` or `>=22.22.0`.
- Use synthetic prompts/data and a dedicated test provider/project.
- Provider calls transmit data externally and can incur cost even when evaluation orchestration is local. Set request/concurrency and spending ceilings.
- Pin model, provider, prompt, tool schema, retrieval corpus revision, and evaluator versions.
- Include allowed and denied controls across roles/tenants; use multiple runs for nondeterministic outcomes.
- Automated red-team labels are leads, not findings. Confirm the real tool call, data access, or side effect manually.
- Store redacted results; evaluation logs can contain system prompts, secrets, retrieved data, and tool arguments.

## Validation

A report must include:

1. initiating identity, tenant, model/runtime, and exact component versions
2. effective-authority map and relevant tool/resource schema
3. untrusted input source and decision boundary crossed
4. exact target-side operation or data access, with redacted audit evidence
5. denied identity/input and allowed control results across repeat runs
6. credential, feature, approval, environment, and user-interaction prerequisites
7. cleanup/revocation and a bounded regression case

## Chaining Attacks

Agentic primitives chain through:

- **Agent + classic vuln**: an agent with a `fetch_url` tool reaches an internal service — load `ssrf`; an agent with a `shell_exec` tool runs commands — load `rce`; an agent with an SQL tool runs queries — load `sql_injection`.
- **Tool-metadata injection + confused deputy**: a document the agent summarizes contains instructions that the agent follows → load `llm_prompt_injection` for the attack primitive, this skill for the authority bypass.
- **Memory poisoning + persistence**: inject tool-call-shaped content into memory → next session executes without new prompt → persistent-RCE-adjacent capability.
- **DNS rebinding + loopback MCP → tool invocation**: attacker's web page reaches local MCP server → arbitrary tool call with user's auth.
- **Token pass-through + privilege expansion**: upstream user token used downstream at a service with broader scope.
- **Cross-client instance reuse → cross-user data leak**: stateless deployment pattern.
- **Agent + business logic → scalping/API6:2023**: agent operates at machine speed, violates business invariants — load `business_logic`.

## False Positives

- The model claims a tool ran but the target and audit log show no action.
- A listed tool cannot be invoked by the tested identity or validates arguments safely.
- A safety refusal changes wording but effective capability remains denied.
- Cross-session output is synthetic, cached public data, or hallucinated rather than another user's data.
- A scanner flags an instruction string without showing that it reaches a privileged decision or sink.
- A component has broad declared permissions but the runtime credential/network policy prevents the claimed access.

## Impact

- Unauthorized action at a downstream target (via confused-deputy chain)
- Cross-user or cross-tenant data access (via instance reuse, memory sharing)
- Local filesystem compromise (via memory TOCTOU)
- Credential exfiltration (via token pass-through or log exposure)
- Business-logic abuse at machine speed (API6:2023)
- Supply-chain compromise (via tool rug-pull or compromised MCP server)
- Audit-log laundering (actions attributed to agent, not to responsible user)
- Persistent compromise via poisoned memory

## Pro Tips

1. Map authority before injecting prompts; don't test what you haven't modeled.
2. Treat tool metadata (names, descriptions, examples, hints) as untrusted — never as authorization.
3. Canonicalize tool identity as `server+version+transport+name+schema-digest`; two identically-named tools are distinct identities.
4. Approval must bind arguments at approval time and re-verify at execution — a generic "continue?" is weak.
5. Memory tools are a persistent attack surface; test TOCTOU and cross-session isolation.
6. For MCP, inspect the transport-level security (OAuth audience, DNS rebinding protection, origin checks) before the tool-level security.
7. Verify at the target's audit log, not the agent's narration.
8. Prove with a dry-run before testing a consequential action; agents are not reversible.
9. Cross-tenant tests require different tenants in test mode; synthetic data in each.
10. Treat the agent's installed skills/plugins/servers as supply chain — each one is executable.

## Summary

Agent security is capability security. Map the real authority carried through models, tools, credentials, plugins, and delegated agents; validate authorization and approval at the target-side effect; treat every installed component as executable supply chain; and preserve each confirmed boundary failure as a bounded regression. The 2024–2026 frontier is dense with verified CVE instances in MCP SDKs, LangChain, LangSmith, and Anthropic's own SDK — each a template for a reusable primitive. Load `agentic_system_security_advanced_deep` for full technique treatments; load `agentic_system_security_novel_deep` for the verified 2024–2026 CVE catalog and research-grade framing.
