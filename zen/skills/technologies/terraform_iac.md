---
name: terraform_iac
description: Terraform and IaC security testing covering plaintext secrets in state files, local-exec and external data source RCE primitives, malicious module supply chain, remote-backend exposure, and plan-time code execution in CI
---

# Terraform IaC

Terraform's attack surface spans the full lifecycle: state files contain plaintext secrets regardless of the `sensitive` flag, execution primitives (`local-exec`, `remote-exec`, `external` data source) run arbitrary commands at plan or apply time, and `terraform init` fetches and executes provider binaries and module code from external sources. This skill owns the Terraform-specific platform surface — state exposure, execution primitives, module/provider supply chain, and backend misconfiguration. The CI-execution context (how Terraform plan/apply runs in CI pipelines) routes to `cicd_platforms`; dependency-confusion and package-identity methodology routes to `supply_chain/npx_confusion`; infrastructure ownership drift routes to `supply_chain/infrastructure_lifecycle`.

## Attack Surface

**State Files**
- `terraform.tfstate` / `terraform.tfstate.backup` — JSON file containing all resource attributes in plaintext
- Remote backends: S3, GCS, Azure Blob, Terraform Cloud/Enterprise, Consul, HTTP
- State locking: DynamoDB (AWS), GCS (built-in), Azure Blob leases
- `terraform output -json` exposes sensitive outputs; `terraform state pull` dumps full state

**Execution Primitives**
- `local-exec` provisioner: runs shell commands on the operator/CI-runner host at apply time
- `remote-exec` provisioner: runs commands on the provisioned resource via SSH/WinRM
- `external` data source: runs arbitrary programs at **plan** time — the plan-time RCE primitive
- Provider binaries: downloaded during `init`, executed during plan/apply — provider = code execution

**Module and Provider Supply Chain**
- Terraform Registry (registry.terraform.io): public modules and providers
- Git-sourced modules: `source = "git::https://..."`; tag/branch/commit ref
- go-getter: library used by `terraform init` to fetch modules (has carried RCE CVEs)
- Provider lock file: `.terraform.lock.hcl` — integrity hashes for downloaded providers

**Backend and Workspace**
- Remote state: read/write access to the backend determines who can read secrets and who can modify infrastructure state
- Workspaces: logical separation within a backend; shared credentials across workspaces
- Terraform Cloud/Enterprise: API tokens (`TFE_TOKEN`), user/team/org scoped; run triggers, VCS integration

## Reconnaissance

**Fingerprinting** (repository-available targets)
```
# Terraform file discovery
find <repo> -name '*.tf' -o -name '*.tfvars' -o -name 'terraform.tfstate*'

# Backend configuration
grep -rn 'backend\s' <repo>/*.tf <repo>/**/*.tf
# Look for: S3 bucket, GCS bucket, Azure container, Terraform Cloud org/workspace

# Provider versions and lock file
cat <repo>/.terraform.lock.hcl
# Reveals provider sources and integrity hashes

# Module sources (external dependencies)
grep -rn 'source\s*=' <repo>/*.tf <repo>/**/*.tf | grep -v '#'
# Registry modules: "hashicorp/consul/aws"; Git: "git::https://..."; local: "./modules/..."

# Sensitive values in state (if state file accessible)
cat terraform.tfstate | grep -i 'password\|secret\|key\|token\|private'

# CI pipeline Terraform steps
grep -rn 'terraform\s\+\(plan\|apply\|init\)' <repo>/.github/workflows/ <repo>/.gitlab-ci.yml
```

**Deployment signals**
- `.tf` files in repository root or `infrastructure/`/`terraform/` subdirectories
- `.terraform/` directory (local provider cache — should be gitignored but sometimes committed)
- `terraform.tfstate` in repository (should never be committed — finding if present)
- CI pipeline steps running `terraform plan`/`apply`

## Key Vulnerabilities

### Plaintext Secrets in State

Terraform state stores every resource attribute — including passwords, API keys, TLS private keys, and database connection strings — in plaintext JSON. The `sensitive = true` marker on variables and outputs suppresses display in plan/apply CLI output but does **not** protect the value in the state file.

Measured on Terraform 1.9.8: a `random_password` resource with `sensitive = true` stores the generated password in plaintext in `terraform.tfstate`. `terraform output -json` also reveals sensitive outputs. The state file is the authoritative plaintext credential exposure vector.

- **Local state file committed to git:** `terraform.tfstate` in a repository exposes every managed secret to anyone with repo read access.
- **Remote backend misconfiguration:** S3 bucket without restrictive bucket policy, GCS bucket with `allUsers` read, Azure Blob container with overly broad SAS tokens — unauthorized state read exposes all managed secrets.
- **State file in CI artifacts:** some CI pipelines store state as a build artifact or cache — accessible to any job in the pipeline.

### Execution Primitives — Plan-Time and Apply-Time RCE

**`external` data source (plan-time RCE):**

Measured on Terraform 1.9.8: the `external` data source runs an arbitrary program during `terraform plan` — not just `apply`. A configuration with `data "external" "cmd" { program = ["bash", "-c", "..."] }` executes the command when the plan is computed. This means `terraform plan` on attacker-controlled configuration is code execution on the operator workstation or CI runner. Route the CI-execution context to `cicd_platforms`.

**`local-exec` provisioner (apply-time RCE):**

Measured on Terraform 1.9.8: `local-exec` provisioner runs commands via `/bin/sh -c` as the Terraform-executing user with no sandbox or isolation. Observed: `id && whoami && pwd` executed as `uid=1000(kali)` with full group membership including `docker` and `sudo`. A malicious module containing a `local-exec` provisioner achieves code execution on the operator or CI runner at apply time.

**`remote-exec` provisioner:** executes commands on the provisioned resource via SSH/WinRM — the intended use case, but a malicious module can use it to pivot from the Terraform execution context to managed infrastructure.

### Malicious Modules and Provider Supply Chain

- **Registry module hijacking:** Terraform Registry modules are referenced by namespace/name/provider; if a module is deleted or transferred, the namespace can potentially be reclaimed. BoostSecurity research documented registry module tag mutation and pwn-request class vulnerabilities.
- **Git-sourced modules without commit-SHA pinning:** `source = "git::https://github.com/org/module.git?ref=v1.0"` — a tag can be force-pushed; pin to a commit SHA for integrity.
- **go-getter RCE (CVE classes in the module-fetch library):**
  - **CVE-2024-6257** (CVSS 8.4) — go-getter: Git configuration injection during module fetch → arbitrary code execution during `terraform init`.
  - **CVE-2024-3817** (CVSS 9.8) — go-getter: argument injection in Git branch discovery → code execution during module fetch.
- **Provider binaries:** `terraform init` downloads and executes provider binaries. A malicious or compromised provider runs arbitrary code. The provider lock file (`.terraform.lock.hcl`) provides integrity verification — its absence or staleness is a finding.

### Terraform CLI and Enterprise CVEs

- **CVE-2023-4782** (CVSS 6.3) — Terraform CLI 1.0.8–1.5.6: arbitrary file write during `terraform init` on a malicious configuration. Fixed in 1.5.7.
- **CVE-2025-13432** (CVSS 4.3) — Terraform Enterprise: insufficient authorization allows a user to create state versions in an unauthorized workspace.
- **CVE-2023-3114** (CVSS 5.0) — Terraform Enterprise: agent pool authorization bypass allowing workspace targeting by unauthorized agents.

### Provider Credential Exposure

- **Credentials in `.tf` files or `.tfvars`:** hardcoded AWS keys, Azure service principal secrets, GCP service account JSON, database passwords in provider or resource configuration.
- **Environment variables:** `AWS_ACCESS_KEY_ID`/`AWS_SECRET_ACCESS_KEY`, `ARM_CLIENT_SECRET`, `GOOGLE_CREDENTIALS` — leaked in CI logs, process listings, or container environment.
- **Terraform Cloud/Enterprise API tokens:** `TFE_TOKEN` grants read/write to state, run triggers, and workspace configuration. Org-level tokens grant access to all workspaces. Token rotation and scope are the mitigations — leaked tokens in CI variables, dotfiles, or shell history are the finding.

### Remote Backend and Workspace Abuse

- **Unauthorized state read/write:** if the backend (S3/GCS/Azure) allows broader access than intended, an attacker reads secrets from state or writes a modified state to alter infrastructure on next apply.
- **Cross-workspace pivot:** workspaces within a single backend share the same backend credentials — compromise of one workspace's state grants access to modify any workspace's state if the backend IAM is workspace-unaware (e.g., a single S3 bucket with one IAM policy for all workspaces).
- **State file manipulation:** an attacker with backend write access modifies the state to add a `local-exec` provisioner that runs on next `terraform apply`, or to modify resource attributes that affect infrastructure behavior.

## Testing Methodology

1. **Repository scan** — find `.tf`, `.tfvars`, `.tfstate`, `.terraform.lock.hcl`, and `.terraform/` files; identify backend configuration, module sources, and provider versions.
2. **State file exposure** — check for committed state files in git history (`git log --all --diff-filter=A -- '*.tfstate'`); test remote backend access controls (S3 bucket policy, GCS IAM, Azure RBAC).
3. **Credential scan** — grep `.tf`/`.tfvars` for hardcoded credentials; check CI variables for plaintext secrets; review provider configuration for credential handling.
4. **Execution primitive review** — search for `local-exec`, `remote-exec`, `external` data sources, and provider `provisioner` blocks; assess whether untrusted input reaches these primitives.
5. **Module/provider integrity** — verify module sources use commit-SHA pinning; confirm `.terraform.lock.hcl` is committed and up-to-date; check for modules from untrusted or personal namespaces.
6. **CI integration** — review how `terraform plan`/`apply` runs in CI; confirm plan runs on PRs do not execute attacker-controlled configs with production credentials. Route to `cicd_platforms`.

## Validation

1. State-file secrets: show a plaintext password/key in `terraform.tfstate` that the `sensitive` flag hides in CLI output but not in state.
2. Plan-time RCE: show `terraform plan` executing an `external` data source program on attacker-controlled config.
3. Apply-time RCE: show `local-exec` provisioner executing OS commands as the Terraform user.
4. Backend exposure: show unauthorized read of remote state containing secrets.
5. Module supply chain: show a Git-sourced module without commit-SHA pinning, or a go-getter CVE version match.

## False Positives

- `sensitive = true` in CLI output — the value IS protected in plan/apply display; the finding is its presence in the state file and `terraform output -json`, not the CLI display.
- `.terraform/` directory in `.gitignore` — this is correct practice; the finding is when it is committed or when the lock file is absent.
- `local-exec` provisioners in trusted, internally-maintained modules — down-rate vs untrusted external modules; the finding is the execution primitive in the context of supply-chain risk.
- Remote backend with proper IAM scoping — confirm actual access controls before reporting; a properly-scoped S3 bucket policy is not a finding.
- Terraform Cloud tokens with team-level scope and rotation — down-rate vs org-level tokens with no rotation.

## Impact

- Mass credential exposure via plaintext secrets in state files — database passwords, API keys, TLS private keys, cloud credentials for every managed resource.
- Remote code execution on operator workstations and CI runners via `external` data source (plan time) or `local-exec` provisioner (apply time).
- Supply-chain compromise via malicious modules or providers — code execution during `init`/`plan`/`apply`.
- Infrastructure manipulation via unauthorized state write — modify resource attributes, inject provisioners, or delete resources.
- Lateral movement from Terraform execution context to managed infrastructure via provider credentials and `remote-exec`.

## Pro Tips

1. `terraform.tfstate` in git history is the fastest win — `git log --all --diff-filter=A -- '*.tfstate'` finds state files that were committed and later removed but remain in history.
2. The `external` data source is the plan-time RCE primitive — `terraform plan` on untrusted config is code execution, not a read-only operation. This is the CI-runner-RCE vector.
3. `sensitive = true` is a display flag, not a security control — it does not encrypt or redact the value in state. Treat every state file as containing plaintext secrets.
4. go-getter CVEs (CVE-2024-6257, CVE-2024-3817) affect `terraform init` — the module-fetch step runs before any plan/apply, making init itself an attack surface.
5. Pair with `cicd_platforms` for the CI execution context; `cryptographic_failures` and `information_disclosure` for credential exposure patterns; `rce` for exploitation methodology; `supply_chain/infrastructure_lifecycle` for module ownership drift.

## Summary

Terraform's security surface is defined by three properties: state files store all secrets in plaintext regardless of the `sensitive` flag, execution primitives (`external` at plan time, `local-exec`/`remote-exec` at apply time) run arbitrary commands with no sandbox, and `terraform init` downloads and executes provider and module code from external sources. The state file is the primary credential exposure vector; the `external` data source is the plan-time RCE primitive that makes `terraform plan` on untrusted config equivalent to code execution; and the go-getter library has carried RCE CVEs that fire during module fetch.
