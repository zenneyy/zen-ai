---
name: trivy
description: Trivy CLI reference — subcommand selection, scanner selection, severity filters, and automation-safe output patterns.
---

# Trivy CLI Playbook

Official docs:
- https://trivy.dev/latest/docs/
- https://trivy.dev/latest/docs/references/configuration/cli/trivy/
- https://github.com/aquasecurity/trivy

Canonical syntax:
`trivy [global flags] <command> [flags] <target>`

Subcommands worth knowing:
- `image <ref|archive>` scan a container image (registry ref or tar archive via `--input`)
- `filesystem <path>` (`fs`) scan a local filesystem path
- `repository <url|path>` (`repo`) scan a git repo (remote URL or local checkout)
- `rootfs <path>` scan an extracted rootfs
- `sbom <file>` scan an SBOM (CycloneDX/SPDX) for vulnerabilities + licenses
- `config <path>` scan IaC configs (Terraform, Kubernetes, Dockerfile, CloudFormation)
- `kubernetes` scan a live cluster (experimental)

High-signal flags:
- `-f, --format <table|json|cyclonedx|spdx|spdx-json|sarif|github|cosign-vuln|template>` output format
- `-o, --output <file>` write report to file
- `-s, --severity <levels>` filter by severity (`CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN`)
- `--scanners <list>` which scanners to run (`vuln,misconfig,secret,license,crypto`)
- `--pkg-types <os,library>` restrict package types evaluated
- `--ignore-unfixed` only report vulns with a fixed version
- `--ignore-status <list>` ignore vulns by status (`will_not_fix,fix_deferred,end_of_life,not_affected,affected,under_investigation,unknown,fixed`)
- `--ignorefile <file>` suppress IDs listed in `.trivyignore` (empty string disables)
- `--ignore-policy <file>` Rego policy file to evaluate each vulnerability
- `--skip-dirs <list>` / `--skip-files <list>` exclude paths (glob)
- `--offline-scan` disable network calls after DB sync
- `--timeout <dur>` global timeout (default `5m`)
- `--cache-dir <path>` cache dir (DB + fanal caches; default `~/.cache/trivy`)
- `--exit-code <n>` return non-zero when findings exist (0 by default)
- `-q, --quiet` suppress progress/log noise
- `--list-all-pkgs` include non-vulnerable packages in reports (default true for JSON)
- `--dependency-tree` show dependency origin tree of vulnerable packages (experimental)
- `--detection-priority <precise|comprehensive>` FP/FN tradeoff (default `precise`)
- `--parallel <n>` scanning goroutines (default 5; 0 = auto)
- `--include-dev-deps` include dev dependencies (npm, yarn, gradle)
- `--pkg-relationships <list>` filter by relationship (`root,workspace,direct,indirect,unknown`)
- `--compliance <string>` generate a compliance report
- `--show-suppressed` show suppressed vulnerabilities (experimental)
- `--secret-config <file>` path to secret scanning config (default `trivy-secret.yaml`)
- `-c, --config <file>` config file path (default `trivy.yaml`; empty disables)
- `-d, --debug` debug mode
- `--insecure` allow insecure TLS connections
- `--cacert <file>` PEM CA cert for server verification
- `--generate-default-config` write `trivy-default.yaml` for reference
- `--disable-telemetry` disable usage data reporting

Agent-safe baseline for automation:
`trivy fs --scanners vuln,secret,misconfig --severity CRITICAL,HIGH --format json -o trivy.json --quiet --timeout 10m /workspace`

Common patterns:
- Scan a local project tree for vulns + secrets + IaC misconfig:
  `trivy fs --scanners vuln,secret,misconfig --severity CRITICAL,HIGH --format json -o trivy.json /workspace`
- Scan a container image (pulled or local):
  `trivy image --severity CRITICAL,HIGH --format json -o trivy_img.json target.tld/app:latest`
- Scan an image archive without pulling (`docker save` output):
  `trivy image --input app.tar --format json -o trivy_img.json`
- Repository scan for vulns + secrets:
  `trivy repo --scanners vuln,secret --format sarif -o trivy_repo.sarif https://github.com/org/repo`
- Scan an SBOM for CVEs:
  `trivy sbom --format json -o trivy_sbom.json sbom.cdx.json`
- IaC-only config scan (Terraform/K8s/Dockerfile):
  `trivy config --severity HIGH,CRITICAL --format json -o trivy_iac.json ./infra`
- Only ever-fixed vulns, SPDX output for supply-chain pipelines:
  `trivy fs --ignore-unfixed --format spdx-json -o trivy_sbom.spdx.json /workspace`
- Comprehensive detection (more findings, more FPs):
  `trivy fs --detection-priority comprehensive --scanners vuln,secret --format json -o trivy_comp.json /workspace`

Critical correctness rules:
- Always pass an explicit subcommand (`fs`/`image`/`repo`/…) — the top-level help prints usage but doesn't scan.
- `--severity` filters AFTER the scan; it does not reduce DB load. Use it for signal, not for speed.
- `--scanners` is the real scope control — drop scanners you don't need (`vuln,secret,misconfig,license`).
- `--ignore-unfixed` is critical for reporting prioritization in CVE workflows; drop it only when you want the full catalog.
- Trivy caches the vuln DB under `~/.cache/trivy`; the first run on a fresh container downloads it (large). Pre-warm the cache or set `--cache-dir` to a persistent path.
- JSON output is the structured one for downstream chaining; SARIF for GitHub/Code-Scanning; CycloneDX/SPDX for supply chain. Pick deliberately per consumer.
- `--offline-scan` requires a pre-warmed cache and will produce stale results if that cache lags.
- `--exit-code 1` only when the pipeline should fail on findings; leave at default `0` otherwise so downstream tools still parse the report.

Usage rules:
- Pin a timeout (`--timeout 10m` for large images) — the default is 5m and silently truncates.
- Use `--quiet` in automation to keep stdout to the report only.
- Keep secrets scan on (`--scanners vuln,secret,...`) for `fs`/`repo` — the misses are expensive to find later.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- DB download fails or stale: `trivy image --download-db-only` (or `--reset`) to force a fresh DB.
- Scans slow and dominated by one path: add `--skip-dirs node_modules,vendor,.venv` before tightening scanners.
- Zero findings on a known-vulnerable image: verify the OS/distro is one trivy supports (some minimal images report no OS) and that `--pkg-types` isn't filtering.
- Rate-limited pulling from a registry: use `--input <tar>` with a locally saved image instead.

If uncertain, query web_search with:
`site:trivy.dev trivy <subcommand> <flag>`

---

## Subcommand Deep-Dive

Each subcommand has a distinct target shape and flag surface. Pick the one that matches your input:

### `trivy filesystem` / `trivy fs`

Scans a local directory tree. Detects: lockfile vulnerabilities, IaC misconfigs, embedded secrets, license violations.

```bash
trivy fs --scanners vuln,secret,misconfig --severity CRITICAL,HIGH \
  --format json -o trivy_fs.json --quiet /workspace
```

Unique behavior: cache backend defaults to `memory` (no persistent scan cache). For repeated scans of the same tree, use `--cache-backend fs` to enable the fanal cache.

`fs` is the default subcommand for local pentesting workflows — it sees everything on disk including untracked files, vendored code, and IaC configs.

### `trivy image` / `trivy i`

Scans a container image by pulling layers and analyzing OS packages + application dependencies.

Image-specific flags:
- `--input <file>` scan a tar archive (`docker save` output) instead of pulling
- `--platform <os/arch>` select a specific platform from a multi-arch manifest
- `--image-src <docker,containerd,podman,remote>` source priority order (default: docker,containerd,podman,remote)
- `--image-config-scanners <misconfig,secret>` scan image config (Dockerfile instructions) separately
- `--docker-host <socket>` / `--podman-host <socket>` custom daemon socket
- `--removed-pkgs` detect vulnerabilities in removed packages (Alpine only)
- `--max-image-size <size>` skip images larger than this (experimental; e.g. `500MB`)

Cache backend defaults to `fs` (persistent layer cache — speeds up re-scans of the same base image).

```bash
trivy image --severity CRITICAL,HIGH --ignore-unfixed \
  --format sarif -o trivy_img.sarif target.tld/app:v1.2.3
```

Multi-arch image (scan only linux/amd64):
```bash
trivy image --platform linux/amd64 --format json -o trivy_amd64.json target.tld/app:latest
```

Scan from a saved tar:
```bash
docker save app:latest -o app.tar
trivy image --input app.tar --format json -o trivy_saved.json
```

### `trivy repository` / `trivy repo`

Scans a git repository — remote URL (clones it) or local checkout. Same scanner surface as `fs` but adds repo-specific flags:

- `--branch <name>` scan a specific branch
- `--commit <hash>` scan a specific commit
- `--tag <name>` scan a specific tag

```bash
trivy repo --branch release/v2 --scanners vuln,secret \
  --format json -o trivy_repo.json https://github.com/org/repo
```

For local checkouts, `trivy fs` is usually faster (no clone overhead). Use `repo` when you need to target a specific ref without checking it out, or for scanning remote repos directly.

### `trivy rootfs`

Scans an extracted root filesystem. Useful for analyzing container images that have been extracted, disk images, or chroot environments.

```bash
trivy rootfs --scanners vuln --severity CRITICAL,HIGH \
  --format json -o trivy_rootfs.json /mnt/extracted-image/
```

`rootfs` differs from `fs` in that it treats the target as a complete OS root — it detects the OS distribution and matches OS-level packages against the vulnerability DB. `fs` treats the target as an application tree.

### `trivy sbom`

Scans an existing SBOM (CycloneDX or SPDX) for known vulnerabilities and license issues. Does not generate the SBOM — it consumes one.

```bash
trivy sbom --format json -o trivy_sbom_vulns.json sbom.cdx.json
```

Use when a project already has an SBOM in its supply-chain pipeline and you want to check it for newly disclosed CVEs without re-scanning the source.

### `trivy config`

IaC-only config scanning — equivalent to `trivy fs --scanners misconfig` but with config as the only scanner. Scans Terraform, Kubernetes manifests, Dockerfiles, CloudFormation, Ansible, Helm charts.

```bash
trivy config --severity HIGH,CRITICAL --format json -o trivy_iac.json ./infra
```

Prefer `trivy config` over `trivy fs --scanners misconfig` when you want clean separation between vuln scanning and IaC scanning in the pipeline.

### Subcommand selection matrix

| Input                         | Subcommand | Notes                                          |
|-------------------------------|------------|-------------------------------------------------|
| Local source tree             | `fs`       | Default for pentest workflows                   |
| Container image (registry)    | `image`    | Pulls layers; use `--platform` for multi-arch   |
| Container image (tar)         | `image`    | `--input app.tar`                               |
| Remote git repo               | `repo`     | Clones; `--branch`/`--commit`/`--tag` to scope  |
| Local git checkout            | `fs`       | Faster than `repo` on local checkouts           |
| Extracted rootfs / disk image | `rootfs`   | OS detection + pkg matching                     |
| Existing SBOM                 | `sbom`     | CVE check on a pre-built SBOM                   |
| IaC configs only              | `config`   | Terraform/K8s/Dockerfile/CloudFormation/Ansible  |

---

## Scanner Configuration

`--scanners <list>` controls which scanners run. Multiple scanners stack:

| Scanner    | Detects                                                | Default on `fs` |
|------------|--------------------------------------------------------|-----------------|
| `vuln`     | CVEs in OS packages + language dependencies            | yes             |
| `secret`   | Embedded secrets (API keys, tokens, passwords)         | yes             |
| `misconfig`| IaC misconfigurations (Dockerfile, Terraform, K8s, …)  | no              |
| `license`  | License violations in dependencies                     | no              |
| `crypto`   | Cryptographic issues (experimental)                    | no              |

Always set `--scanners` explicitly for reproducible results — the default set varies by subcommand.

### vuln scanner

The vulnerability scanner matches OS packages and language-specific dependencies against the trivy-db. It supports:
- OS packages: Alpine, Debian, Ubuntu, RHEL/CentOS, Amazon Linux, SUSE, Arch, Wolfi, Chainguard, CBL-Mariner, and more
- Language lockfiles: npm, yarn, pnpm, pip, poetry, pipenv, Go modules, Cargo, Maven, Gradle, NuGet, Composer, Conan, Swift, Pub, Hex, Julia

Key vuln-specific flags:
- `--ignore-unfixed` only show vulns with a fix version available
- `--ignore-status <list>` ignore vulns by status (e.g. `will_not_fix,end_of_life`)
- `--vuln-severity-source <list>` order of severity data sources (default `auto` — trivy picks the most relevant for the distro)
- `--vex <sources>` consume VEX documents to suppress known-not-affected vulns (experimental; `repo`, `oci`, or file path)
- `--include-dev-deps` include dev dependencies (npm, yarn, gradle — default is production-only)
- `--pkg-relationships <list>` filter by dependency relationship (root, workspace, direct, indirect)

### misconfig scanner

Detects IaC misconfigurations using built-in checks (OPA/Rego) and the trivy-checks bundle. Covers: Terraform, Kubernetes manifests, Dockerfiles, CloudFormation, Ansible playbooks, Helm charts, Azure ARM, Terraform plan JSON/snapshot.

Enabled by adding `misconfig` to `--scanners`. See the IaC Misconfig section below for flag details.

### secret scanner

Pattern-based secret detection in source files. Uses rules defined in `trivy-secret.yaml` (default) or a custom config via `--secret-config`. Lighter than gitleaks/trufflehog — no git history traversal, no live verification. Use it as a complement, not a replacement.

### license scanner

Dependency license detection. `--license-full` eagerly scans source headers and license files (not just metadata). Use `--ignored-licenses` to suppress acceptable licenses. See License Scanning section below.

---

## IaC Misconfig Scanning

Trivy's misconfig scanner evaluates IaC files against a bundle of built-in Rego checks. Each IaC type has specific flags.

### Misconfig scanner selection

`--misconfig-scanners <list>` controls which IaC parsers run:

Default set: `azure-arm,cloudformation,dockerfile,helm,kubernetes,terraform,terraformplan-json,terraformplan-snapshot,ansible`

Narrow it when you know what's in the target to reduce noise and runtime:
```bash
trivy fs --scanners misconfig --misconfig-scanners terraform,dockerfile \
  --format json -o trivy_iac.json ./infra
```

### Terraform

- `--tf-vars <files>` override `terraform.tfvars` (repeatable)
- `--tf-exclude-downloaded-modules` skip misconfigs in `.terraform/modules/` (downloaded third-party modules)
- `--render-cause terraform` show the Terraform source location that triggered the misconfig in table output
- `--raw-config-scanners terraform` scan the raw (unadapted) Terraform config into a shared state

```bash
trivy fs --scanners misconfig --misconfig-scanners terraform \
  --tf-vars envs/prod.tfvars --tf-exclude-downloaded-modules \
  --render-cause terraform --severity HIGH,CRITICAL \
  --format json -o trivy_tf.json ./terraform
```

### Helm

- `--helm-values <files>` override `values.yaml` (repeatable)
- `--helm-set <key=val>` inline value overrides (repeatable)
- `--helm-set-string <key=val>` string value overrides
- `--helm-set-file <key=path>` file value overrides
- `--helm-kube-version <version>` Kubernetes version for `Capabilities.KubeVersion`
- `--helm-api-versions <list>` available API versions for `Capabilities.APIVersions`

```bash
trivy fs --scanners misconfig --misconfig-scanners helm \
  --helm-values values-prod.yaml --helm-kube-version 1.28 \
  --format json -o trivy_helm.json ./charts/app
```

### Ansible

- `--ansible-playbook <files>` playbook file paths to scan (repeatable)
- `--ansible-inventory <hosts>` inventory host path or comma-separated host list
- `--ansible-extra-vars <key=value|@file>` additional variables
- `--render-cause ansible` show Ansible source location in table output

### CloudFormation

- `--cf-params <files>` parameter override files (repeatable)

### Dockerfile

No Dockerfile-specific flags — the Dockerfile misconfig scanner runs by default when `misconfig` is in `--scanners` and Dockerfiles are present.

### Compliance pass/fail

`--include-non-failures` includes passing checks in the output — useful for compliance reports where you need to show what passed, not just what failed:

```bash
trivy fs --scanners misconfig --include-non-failures \
  --format json -o trivy_compliance_full.json ./infra
```

### Checks bundle

`--checks-bundle-repository <oci_url>` points to an alternate OCI registry for the trivy-checks bundle (default: `mirror.gcr.io/aquasec/trivy-checks:2`). Use for air-gapped environments or custom check bundles.

---

## Rego Custom Checks

Trivy supports custom OPA/Rego policies for misconfig scanning. Use these when the built-in checks don't cover your organization's policy requirements.

- `--config-check <paths>` paths to Rego check files or directories (repeatable)
- `--config-data <paths>` paths to data files consumed by the Rego checks (recursively loaded)
- `--check-namespaces <namespaces>` Rego namespaces to query (default: built-in namespaces)
- `--config-file-schemas <paths>` JSON schemas that help Rego type-check config files
- `--trace-rego` verbose trace output for custom queries (debugging)
- `--rego-error-limit <n>` max compile errors before aborting (default 10)
- `--include-deprecated-checks` include deprecated built-in checks
- `--skip-check-update` skip fetching Rego check updates (use with a pinned bundle)

Minimal custom check workflow:

```bash
# 1. Write a Rego check
cat > checks/no_latest_tag.rego <<'REGO'
package custom.dockerfile

import rego.v1

deny contains res if {
    instruction := input.Stages[_].Commands[_]
    instruction.Cmd == "from"
    endswith(instruction.Value[0], ":latest")
    res := {
        "msg": "Avoid using ':latest' tag",
        "id": "CUSTOM-001",
        "severity": "HIGH",
    }
}
REGO

# 2. Run trivy with the custom check
trivy fs --scanners misconfig --config-check ./checks/ \
  --check-namespaces custom --severity HIGH,CRITICAL \
  --format json -o trivy_custom.json .
```

Debug a failing custom check with `--trace-rego`:
```bash
trivy fs --scanners misconfig --config-check ./checks/ \
  --check-namespaces custom --trace-rego .
```

Supply data files to Rego checks (e.g. lists of approved registries, allowed configurations):
```bash
trivy fs --scanners misconfig --config-check ./checks/ \
  --config-data ./policy-data/ --check-namespaces custom .
```

---

## License Scanning

Enable with `--scanners license` (or stack: `--scanners vuln,license`).

- `--license-full` eagerly scan source code headers and license files (not just package metadata). Slower but catches vendored/forked code with non-obvious licenses.
- `--ignored-licenses <list>` suppress specific license identifiers (SPDX; repeatable). Use for licenses your organization has pre-approved.
- `--license-confidence-level <float>` classifier confidence threshold (default 0.9). Lower values catch more licenses at the cost of false positives.

```bash
trivy fs --scanners license --license-full \
  --ignored-licenses MIT,Apache-2.0,BSD-3-Clause \
  --format json -o trivy_license.json /workspace
```

Combined SCA + license scan:
```bash
trivy fs --scanners vuln,license --license-full --severity HIGH,CRITICAL \
  --ignored-licenses MIT,ISC --format json -o trivy_sca.json /workspace
```

---

## Secret Scanning Config

Trivy's secret scanner uses a config file (default: `trivy-secret.yaml` in the scan root). Override with `--secret-config <file>` (empty string disables).

The config file defines:
- Custom secret patterns (regex-based rules)
- Allow rules (suppress known false positives)
- Exclusion paths

Minimal `trivy-secret.yaml`:
```yaml
rules:
  - id: custom-api-key
    category: general
    title: Custom Internal API Key
    severity: HIGH
    regex: 'INTERNAL_KEY_[A-Z0-9]{32}'

allow-rules:
  - id: allow-test-keys
    description: Test fixtures
    regex: 'test_key_[a-z]+'
    path: '.*_test\.go'
```

For deeper secret scanning (git history, live verification), use `tooling/gitleaks.md` and `tooling/trufflehog.md`. Trivy's secret scanner covers the working tree only — no history traversal.

---

## SBOM Generation

Trivy generates SBOMs as output formats, not through a dedicated subcommand. Use `--format` with one of the SBOM formats:

| Format       | Flag value      | Notes                                    |
|--------------|-----------------|------------------------------------------|
| CycloneDX    | `cyclonedx`     | XML; most tool ecosystem support         |
| SPDX         | `spdx`          | Tag-value; legacy format                 |
| SPDX JSON    | `spdx-json`     | JSON; preferred for machine consumption  |
| cosign-vuln  | `cosign-vuln`   | Cosign vulnerability attestation format  |

Generate a CycloneDX SBOM of all packages (including non-vulnerable):
```bash
trivy fs --list-all-pkgs --format cyclonedx -o sbom.cdx.xml /workspace
```

Generate an SPDX JSON SBOM:
```bash
trivy fs --list-all-pkgs --format spdx-json -o sbom.spdx.json /workspace
```

`--list-all-pkgs` is default true for JSON but must be set explicitly for SBOM formats to include all packages (not just vulnerable ones).

SBOM consumption: use `trivy sbom <file>` to scan an existing SBOM for vulnerabilities — this is the inverse operation. The pair is: `trivy fs --format cyclonedx` generates the SBOM; `trivy sbom` consumes one.

---

## DB Management

Trivy's vulnerability database is an OCI artifact pulled on first run and cached locally.

### Cache and DB flags

- `--cache-dir <path>` cache directory (default `~/.cache/trivy`)
- `--download-db-only` download/update the vuln DB without scanning
- `--download-java-db-only` download/update the Java index DB without scanning
- `--skip-db-update` skip DB update (use cached DB as-is)
- `--skip-java-db-update` skip Java DB update
- `--no-progress` suppress download progress bar (for logs)
- `--db-repository <oci_urls>` OCI repositories for trivy-db (default: `mirror.gcr.io/aquasec/trivy-db:2,ghcr.io/aquasecurity/trivy-db:2`)
- `--java-db-repository <oci_urls>` OCI repositories for trivy-java-db

### Pre-warming the cache

In CI or sandboxed environments, pre-warm the DB before the scan:
```bash
trivy image --download-db-only --no-progress --cache-dir /shared/trivy-cache
trivy image --skip-db-update --cache-dir /shared/trivy-cache target.tld/app:latest
```

### Offline scanning

`--offline-scan` prevents all network calls during the scan. Combine with `--skip-db-update` and a pre-warmed cache for air-gapped environments:
```bash
trivy fs --offline-scan --skip-db-update --cache-dir /shared/trivy-cache \
  --format json -o trivy.json /workspace
```

### Mirror repositories

For private registries or air-gapped networks, push the trivy-db OCI artifact to your own registry and point trivy at it:
```bash
trivy image --db-repository my-registry.internal/trivy-db:2 \
  --java-db-repository my-registry.internal/trivy-java-db:1 target.tld/app:latest
```

---

## Compliance Reports

`--compliance <spec>` generates a compliance-framework report mapping findings to specific controls.

Built-in compliance specs (for `image` subcommand):
- `docker-cis-1.6.0` — Docker CIS Benchmark 1.6.0

```bash
trivy image --compliance docker-cis-1.6.0 --report summary target.tld/app:latest
```

`--report <all|summary>` controls compliance report detail level:
- `summary` — aggregated pass/fail per control (default for `image`)
- `all` — full findings per control

Compliance reports combine with `--include-non-failures` to show both passing and failing controls:
```bash
trivy image --compliance docker-cis-1.6.0 --include-non-failures \
  --report all --format json -o compliance.json target.tld/app:latest
```

---

## VEX and Attestation

VEX (Vulnerability Exploitability eXchange) documents let you suppress findings that are known not to affect your deployment.

- `--vex <sources>` VEX sources — `repo` (VEX repository), `oci` (OCI artifact), or a file path to a VEX document (experimental)
- `--skip-vex-repo-update` skip updating the VEX repository (use cached data)
- `--sbom-sources <oci,rekor>` retrieve SBOMs from OCI registries or Rekor transparency logs (experimental)
- `--rekor-url <url>` Rekor STL server address (default `https://rekor.sigstore.dev`)

```bash
# Suppress known-not-affected CVEs using a local VEX document
trivy image --vex vex.openvex.json --format json -o trivy.json target.tld/app:latest

# Use the VEX repository for automatic suppression
trivy image --vex repo --format json -o trivy.json target.tld/app:latest
```

VEX is the mechanism for resolving "CVE found but not exploitable in our context" — use it to reduce noise without losing the audit trail that `.trivyignore` loses.

---

## Client/Server Mode

Trivy can run as a server that caches the vulnerability DB, with lightweight clients sending scan requests to it.

Server-side flags (run once, shared):
```bash
trivy server --listen 0.0.0.0:4954 --token my-secret-token
```

Client-side flags:
- `--server <addr>` server address (e.g. `http://trivy-server:4954`)
- `--token <token>` authentication token
- `--token-header <header>` custom token header name (default `Trivy-Token`)
- `--custom-headers <key:value>` additional headers (repeatable)

```bash
trivy image --server http://trivy-server:4954 --token my-secret-token \
  --format json -o trivy.json target.tld/app:latest
```

Client/server mode avoids DB download on every CI runner — the server maintains the DB, clients are thin. Use it in team environments or CI pipelines where DB download time is a bottleneck.

### Registry auth

For scanning private registries:
- `--username <user>` / `--password <pass>` basic auth (prefer `TRIVY_PASSWORD` env var)
- `--password-stdin` read password from stdin (no shell history)
- `--registry-token <token>` bearer token auth

```bash
echo "$REGISTRY_PASS" | trivy image --username deploy --password-stdin \
  --format json -o trivy.json registry.internal/app:latest
```

---

## Output Ecosystem

### Format matrix

| Format        | Flag               | Use case                                     |
|---------------|--------------------|----------------------------------------------|
| `table`       | `--format table`   | Human-readable terminal output (default)     |
| `json`        | `--format json`    | Structured output for jq/downstream parsing  |
| `sarif`       | `--format sarif`   | GitHub Code Scanning / IDE integration       |
| `cyclonedx`   | `--format cyclonedx` | CycloneDX SBOM (XML)                      |
| `spdx`        | `--format spdx`    | SPDX SBOM (tag-value)                        |
| `spdx-json`   | `--format spdx-json` | SPDX SBOM (JSON)                           |
| `github`      | `--format github`  | GitHub Dependency Snapshot API               |
| `cosign-vuln` | `--format cosign-vuln` | Cosign attestation format                |
| `template`    | `--format template` | Custom Go template (`-t <file.tpl>`)        |

### Table mode

`--table-mode <summary,detailed>` controls table columns (experimental):
- `summary` — compact per-vulnerability view
- `detailed` — includes fix versions, references, descriptions
- Both are on by default; restrict to one for cleaner output

### Custom templates

`--format template -t <file.tpl>` uses a Go template for custom output. The template file must have a `.tpl` extension:

```bash
trivy fs --format template -t report.tpl -o report.txt /workspace
```

### CI gating

`--exit-code <n>` sets the process exit code when findings exist:
```bash
# Gate on CRITICAL+HIGH; exit 2 to fail the pipeline
trivy fs --scanners vuln --severity CRITICAL,HIGH --exit-code 2 \
  --format sarif -o trivy.sarif /workspace
```

Dual output (human-readable to stdout, machine-readable to file):
```bash
trivy fs --scanners vuln,secret --severity CRITICAL,HIGH \
  --format json -o trivy.json /workspace
# Table output goes to stdout by default; JSON goes to the file
```

---

## Triage Methodology

### Severity × fixability matrix

The triage priority for trivy findings combines severity with fixability:

| Priority | Severity  | Fixability     | Action                                |
|----------|-----------|----------------|---------------------------------------|
| P0       | CRITICAL  | Fixed version  | Patch immediately                     |
| P1       | HIGH      | Fixed version  | Patch in current sprint               |
| P2       | CRITICAL  | No fix         | Evaluate workaround / accept risk     |
| P3       | HIGH      | No fix         | Accept risk, add to `.trivyignore`    |
| P4       | MEDIUM+   | Any            | Track, batch-patch                    |

```bash
# P0+P1: actionable, fixable findings
trivy fs --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed \
  --format json -o trivy_actionable.json /workspace

# Full catalog for tracking
trivy fs --scanners vuln --format json -o trivy_full.json /workspace
```

### `.trivyignore` management

The `.trivyignore` file suppresses specific finding IDs:
```
# Accepted risk: no fix available, mitigated by network policy
CVE-2023-12345

# False positive: test fixture
CVE-2024-67890

# Expired: re-evaluate after 2025-01-01
CVE-2024-11111
```

`--ignorefile ""` disables `.trivyignore` loading — useful for audit runs that need the full picture.

`--show-suppressed` (experimental) includes suppressed findings in the output, marked as suppressed — useful for auditing the ignore list itself.

### Rego-based ignore policy

`--ignore-policy <file>` evaluates each vulnerability against a Rego policy. The policy can make accept/reject decisions based on any field in the vulnerability record:

```rego
package trivy

import rego.v1

ignore contains vuln if {
    vuln := input.vulnerability
    vuln.Severity == "LOW"
}

ignore contains vuln if {
    vuln := input.vulnerability
    count(vuln.References) == 0
    vuln.Severity == "MEDIUM"
}
```

```bash
trivy fs --ignore-policy policy.rego --format json -o trivy.json /workspace
```

### Vulnerability status filtering

`--ignore-status <list>` suppresses vulnerabilities by their patch status:
- `will_not_fix` — vendor has stated no fix will be released
- `fix_deferred` — fix is deferred to a future release
- `end_of_life` — package/OS is end-of-life
- `not_affected` — vulnerability does not affect this build/configuration

```bash
# Suppress vulns the vendor won't fix
trivy fs --ignore-status will_not_fix,end_of_life \
  --format json -o trivy.json /workspace
```

### Severity source selection

`--vuln-severity-source <list>` controls which data sources trivy uses for severity scores. Default `auto` picks the most relevant source per package type. Override when you need a specific authority:

```bash
# Use NVD scores exclusively
trivy image --vuln-severity-source nvd --format json -o trivy.json app:latest
```

---

## Tool Chaining

### trivy → vulnx (CVE enrichment)

Trivy finds CVE IDs in your dependencies; vulnx (`tooling/vulnx.md`) enriches them with KEV status, public PoCs, and nuclei template availability:

```bash
trivy fs --scanners vuln --severity CRITICAL,HIGH --format json -o trivy.json /workspace
jq -r '.Results[].Vulnerabilities[]?.VulnerabilityID' trivy.json | sort -u > cve_ids.txt
vulnx id --file cve_ids.txt --json -o enriched.json
```

### trivy + gitleaks/trufflehog (secret coverage)

Trivy's secret scanner covers the working tree with a small rule set. For deeper coverage:
- `tooling/gitleaks.md` — git history traversal, custom TOML rules, archive scanning
- `tooling/trufflehog.md` — live credential verification, remote source adapters

Run trivy secrets alongside gitleaks for complementary coverage:
```bash
trivy fs --scanners secret --format json -o trivy_secrets.json /workspace
gitleaks git --report-format json --report-path gitleaks.json --redact /workspace
```

### trivy + retire (JS depth)

Trivy covers npm/yarn/pnpm lockfiles well. Retire (`tooling/retire.md`) adds JavaScript file fingerprinting — catching vendored/CDN-copied libraries that lockfiles don't know about:
```bash
trivy fs --scanners vuln --format json -o trivy.json /workspace
retire --path /workspace --outputformat json --outputpath retire.json --severity high --exitwith 0
```

### trivy + nuclei (live validation)

Trivy finds CVEs in dependencies; nuclei (`tooling/nuclei.md`) validates whether they're exploitable in a running instance:
```bash
# Extract CVE IDs with nuclei templates
jq -r '.Results[].Vulnerabilities[]? | select(.VulnerabilityID | startswith("CVE-")) | .VulnerabilityID' trivy.json | sort -u > cves.txt
# Check for nuclei templates
vulnx id --file cves.txt --json | jq 'select(.has_nuclei == true) | .cve_id'
```

### trivy + semgrep/bandit (code + deps)

Trivy catches dependency-level issues; semgrep (`tooling/semgrep.md`) and bandit (`tooling/bandit.md`) catch code-level issues. Non-overlapping — run both:
```bash
trivy fs --scanners vuln,secret,misconfig --format json -o trivy.json /workspace
semgrep scan --config p/default --metrics=off --sarif --output semgrep.sarif --quiet /workspace
```

---

Routed consumers:
- `supply_chain/dependency_cve_scanning.md` is the workflow skill for trivy-based SCA — this file is only the operational tool reference; do not duplicate the workflow logic here.
- `tooling/retire.md` for JS/node SCA (complementary — retire is JS-specific, trivy covers OS+most lockfiles).
- `tooling/gitleaks.md` / `tooling/trufflehog.md` when the secret-scanner subset of trivy returns thin — trivy's secret rules are a subset of theirs.
- `tooling/vulnx.md` (CVE enrichment — trivy produces IDs, vulnx enriches with KEV/PoC/template signals)
- `tooling/nuclei.md` (live CVE validation against running targets)
- `tooling/semgrep.md`, `tooling/bandit.md` (code-level findings — complementary to trivy's dependency-level coverage)
- `vulnerabilities/information_disclosure.md` (trivy secret scanner findings)
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
