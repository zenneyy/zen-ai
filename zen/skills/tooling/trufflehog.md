---
name: trufflehog
description: TruffleHog secret scanning — the live-verification counterpart to gitleaks, with native source adapters for GitHub/GitLab/S3/Docker/Postman.
---

# trufflehog CLI Playbook

Official docs:
- https://github.com/trufflesecurity/trufflehog
- https://docs.trufflesecurity.com/

Canonical syntax:
`trufflehog [flags] <command> [args]`

For the shared secret-scanning workflow (git/filesystem/stdin, baselines, SARIF/JSON output, how to feed `information_disclosure`), use `tooling/gitleaks.md` — this file documents only what trufflehog adds.

What trufflehog adds over gitleaks:
- **Live credential verification.** `--results verified,unverified,unknown` sends the matched secret to its real provider (AWS STS, GitHub token API, Slack `auth.test`, etc.) and reports whether it still works. Verified-only output is near-zero-FP; unverified is a rules match of equal strength to gitleaks.
- **First-class remote sources.** `git <uri>`, `github --repo/--org/--token`, `gitlab --token`, `s3`, `gcs`, `docker --image`, `postman`, `jenkins`, `huggingface`, `elasticsearch`, `syslog`, `circleci`, `travisci` — scan without having to clone or download first.
- **Analyze mode.** `trufflehog analyze` on a found token reports fine-grained permissions (what the key can read/write/delete) when the provider API exposes that.

High-signal flags (unique or non-obviously different from gitleaks):
- `--results <list>` filter output by verification status (`verified,unverified,unknown,filtered_unverified`); default `verified,unverified,unknown`.
- `--only-verified` shorthand for `--results verified` on older builds — prefer `--results verified` for clarity on 3.95+.
- `--no-verification` disable live verification entirely (match gitleaks semantics, no outbound verification traffic).
- `-j, --json` JSONL on stdout (not the file-based `--report-format` of gitleaks).
- `--json-legacy` pre-v3 JSON format (git/github/gitlab only).
- `--github-actions` GitHub Actions-formatted output.
- `--include-detectors <list>` / `--exclude-detectors <list>` detector type IDs or ranges (see `trufflehog --help-long`).
- `--filter-entropy <float>` suppress unverified results below a Shannon-entropy threshold (`3.0` is a reasonable floor).
- `--filter-unverified` only output first unverified result per chunk per detector when multiple match — reduces noise without raising entropy threshold.
- `--allow-verification-overlap` allow verification of similar credentials across detectors (default: first match wins). Enable when the same secret could be a valid credential for multiple services.
- `--max-decode-depth <n>` iterative decoding depth (default 5). Each decoder's output is fed through all decoders up to this limit — catches base64-inside-utf16, double-encoded secrets, etc.
- `--config <file>` path to configuration file (custom detectors, allowlists, multi-scan source definitions).
- `--concurrency <n>` worker count.
- `--detector-timeout <dur>` per-detector chunk timeout (e.g. `30s`).
- `--archive-max-size <size>` / `--archive-max-depth <n>` archive handling (same shape as gitleaks).
- `--archive-timeout <dur>` max time extracting a single archive (prevents hangs on crafted archives).
- `--no-verification-cache` disable the verification result cache (re-verify every hit).
- `--verifier <endpoint>` custom verification endpoint (repeatable). The endpoint receives the matched secret and returns verification status.
- `--custom-verifiers-only` use only custom verification endpoints — skip built-in provider verifiers.
- `--print-avg-detector-time` print average time per detector after scan — profiling for large runs.
- `--force-skip-binaries` hard-skip binary files regardless of other settings.
- `--force-skip-archives` hard-skip archive files regardless of other settings.
- `--skip-additional-refs` skip additional git refs beyond HEAD (tags, stashes, remote refs).
- `--user-agent-suffix <string>` append to the default User-Agent header on all outbound requests.
- `--drop-unverified-jwt-results` drop unverified JWT results that have no verification errors (reduces JWT noise).
- `--fail` exit code 183 on findings.
- `--fail-on-scan-errors` fail on scan errors (default is to continue).
- `--no-update` suppress self-update check.

Agent-safe baseline for automation:
`trufflehog filesystem --results verified,unverified --json --no-update --concurrency 8 --detector-timeout 10s /workspace > trufflehog.jsonl`

Common patterns:
- Scan a local tree, verified-only (minimal FP, maximum signal):
  `trufflehog filesystem --results verified --json --no-update /workspace > trufflehog_verified.jsonl`
- Scan a GitHub org without cloning:
  `trufflehog github --org <org> --token "$GITHUB_TOKEN" --results verified --json > trufflehog_org.jsonl`
- Scan a single public repo:
  `trufflehog git https://github.com/<org>/<repo> --results verified,unverified --json > trufflehog_repo.jsonl`
- Scan a Docker image for secrets baked into layers:
  `trufflehog docker --image target.tld/app:latest --results verified --json > trufflehog_img.jsonl`
- Live-check one found token for permissions:
  `trufflehog analyze` (interactive; `--help` for subcommand usage)
- No-verification mode (parity with gitleaks' find-only semantics):
  `trufflehog filesystem --no-verification --json /workspace > trufflehog_find.jsonl`

Critical correctness rules:
- Live verification sends the secret to the vendor API — do this only when the engagement authorizes it; use `--no-verification` otherwise.
- The verification cache persists across runs (`--no-verification-cache` disables it) — rotated-but-not-revoked keys can appear verified until the cache invalidates.
- `--include-detectors`/`--exclude-detectors` are matched by **ID or range**, not by name; grep `trufflehog --help-long | less` for the catalogue before narrowing.
- Exit-code behavior differs from gitleaks: `--fail` returns 183, not 1. Automation that expects a specific non-zero exit must branch on that.
- The sandbox binary at `/home/pentester/.local/bin/trufflehog` is self-updating — `--no-update` prevents the version drift that otherwise shows up mid-scan.

Usage rules:
- Reach for trufflehog when the task needs **live-verified credentials** or a non-git source (S3, Docker, Postman, GitHub-API); use `tooling/gitleaks.md` for the git-history / filesystem bulk sweep.
- Keep JSONL on stdout and redirect to a file; trufflehog has no `--output` flag.
- Set `--filter-entropy 3.0` on unverified passes to tame low-signal matches.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Verified-only output is empty: re-run with `--results verified,unverified,unknown` to see what the detectors matched before verification; a verifier may be rate-limited or offline.
- Network-source scans (`github`, `s3`, `gcs`) failing with auth errors: verify the `--token`/credential and that the sandbox's `HTTP_PROXY` env is honored (trufflehog respects it).
- Trufflehog self-update aborts the scan: re-run with `--no-update`.

---

## Verification Methodology

Trufflehog's defining capability. The scan pipeline:

```
source → chunking → detector match → decoder chain → verifier → result
```

1. **Detector match**: regex/pattern match produces a raw candidate.
2. **Decoder chain**: the candidate passes through decoders (base64, hex, utf16, percent-encoding) up to `--max-decode-depth` (default 5). Each decoder's output is fed back through all decoders, so base64-inside-utf16 is caught without a custom rule.
3. **Verifier**: the decoded secret is sent to the provider's API. AWS keys hit `sts:GetCallerIdentity`; GitHub tokens hit the token metadata endpoint; Slack tokens hit `auth.test`. The response determines status:
   - `verified` — the credential is live and functional.
   - `unverified` — detector matched but the verifier could not confirm (API error, rate limit, network issue, or the key is revoked).
   - `unknown` — the detector has no verifier for this type.
   - `filtered_unverified` — unverified but would have been filtered by `--filter-entropy` or `--filter-unverified`.

Verification cache: results are cached per-secret so repeated scans don't re-verify the same credential. This is correct for most workflows but misleading when a key has been rotated since the last scan. Use `--no-verification-cache` when re-scanning after a credential rotation to force re-verification.

`--allow-verification-overlap`: by default, once a secret is verified by one detector, other detectors that match the same bytes skip verification. Enable overlap when the same secret could be valid for multiple services (e.g. a token that works as both a GitHub PAT and a CircleCI token).

Authorization boundary: verification sends the matched secret to the provider's real API. The engagement must authorize this. For assessments where outbound verification traffic is not permitted, use `--no-verification` — the scan still runs all detectors and decoders, producing output equivalent to gitleaks' pattern-matching.

Timing: verification adds latency per finding. On repos with many matches, `--concurrency` and `--detector-timeout` control throughput:
```bash
trufflehog git https://github.com/org/large-repo \
  --results verified,unverified --json --no-update \
  --concurrency 16 --detector-timeout 15s \
  > trufflehog_large.jsonl
```

---

## Source Adapter Catalogue

Each source has unique flags beyond the global set. The shared git/filesystem basics (cloning, path scanning) overlap with gitleaks — this section covers only the flags and behaviors specific to trufflehog's adapters.

### git

```bash
trufflehog git [flags] <uri>
```

- `--since-commit <hash>` scan only commits after this one (equivalent to gitleaks' `--log-opts "hash..HEAD"` but native).
- `--branch <name>` scan a specific branch.
- `--max-depth <n>` limit commit depth (caps runtime on long-lived repos).
- `--bare` scan a bare repository (useful in pre-receive hooks).
- `--clone-path <path>` custom clone destination (default: temp dir).
- `--no-cleanup` keep the cloned repo after scanning (requires `--clone-path`).
- `-i, --include-paths <file>` / `-x, --exclude-paths <file>` newline-separated regex filters for paths.
- `--exclude-globs <globs>` comma-separated globs applied at the `git log` level — faster than path filtering because git skips blobs entirely.

```bash
trufflehog git https://github.com/org/repo \
  --since-commit abc1234 --branch develop \
  --exclude-globs "*.min.js,vendor/*" \
  --results verified --json --no-update > repo.jsonl
```

### github

```bash
trufflehog github [flags]
```

- `--repo <url>` scan a single repo via the GitHub API.
- `--org <name>` scan all repos in an org.
- `--token <pat>` GitHub PAT (required for private repos, recommended for rate limits).
- `--include-members` include member repos when scanning an org.
- `--include-forks` include forked repos.
- `--include-wikis` scan wiki repos.

Org-wide sweep:
```bash
trufflehog github --org target-org --token "$GH_TOKEN" \
  --include-members --include-forks \
  --results verified --json --no-update > org_secrets.jsonl
```

### github-experimental

```bash
trufflehog github-experimental --repo <url> [flags]
```

Runs experimental sub-modules that find secrets the regular `github` command misses. Currently supports `--object-discovery`, which scans orphaned git objects (unreachable blobs, force-pushed commits, PR diff remnants) via the GitHub API. These objects are not visible in the normal commit history.

```bash
trufflehog github-experimental --repo https://github.com/org/repo \
  --token "$GH_TOKEN" --object-discovery \
  --results verified --json > experimental.jsonl
```

Use when the regular `github` scan returns clean but you suspect force-pushed or squashed commits contained secrets.

### gitlab

```bash
trufflehog gitlab --token <pat> [flags]
```

- `--token <pat>` GitLab PAT (required).
- `--group <name>` scan a GitLab group.
- `--include-subgroups` recurse into subgroups.

### filesystem

```bash
trufflehog filesystem [flags] [path...]
```

- `--directory <path>` explicit directory (repeatable — scan multiple trees in one invocation).
- `-i, --include-paths <file>` / `-x, --exclude-paths <file>` newline-separated regex filters.
- `-s, --max-symlink-depth <n>` follow symlinks up to N levels (default: no follow).

Multiple directories:
```bash
trufflehog filesystem \
  --directory /workspace/app --directory /workspace/config \
  --include-paths include.txt \
  --results verified --json --no-update > fs.jsonl
```

### docker

```bash
trufflehog docker --image <ref> [flags]
```

Scans every layer of the image, including intermediate layers that `docker history` shows as `<missing>`. Catches secrets baked into build stages that were squashed or removed in later layers.

```bash
trufflehog docker --image target.tld/app:v2.3 \
  --results verified --json --no-update > docker_secrets.jsonl
```

### s3 / gcs

```bash
trufflehog s3 [flags]
trufflehog gcs [flags]
```

Scan cloud storage buckets directly. Authentication uses the standard SDK credential chain (env vars, instance profiles, service accounts). Specify buckets with `--bucket` and optionally narrow with `--key` (S3 key prefix).

```bash
trufflehog s3 --bucket target-bucket --key "config/" \
  --results verified --json > s3_secrets.jsonl
```

### Other adapters

Each takes `--token` or `--url` as its primary config:
- `postman --token <key> [--workspace <id>]` — scan Postman collections, environments, and globals.
- `jenkins --url <base> [--username <u> --password <p>]` — scan Jenkins credentials, build configs, and console output.
- `huggingface [--model <id> | --space <id> | --dataset <id>]` — scan HuggingFace assets.
- `elasticsearch --nodes <urls> [--index-pattern <pattern>]` — scan Elasticsearch indices.
- `syslog --format <rfc3164|rfc5424> [--address <host:port>]` — listen for syslog and scan in real time.
- `circleci --token <pat>` — scan CircleCI project environment variables and contexts.
- `travisci --token <pat>` — scan TravisCI build logs and environment variables.

### stdin

```bash
echo "AKIA..." | trufflehog stdin --json
```

Reads from stdin. Useful for one-off checks or piping from another tool's output.

### multi-scan

```bash
trufflehog multi-scan [flags]
```

Runs multiple sources defined in a single `--config` file. Avoids scripting loops for multi-source assessments.

---

## Custom Verification

`--verifier <endpoint>` routes matched secrets to your own verification endpoint instead of (or in addition to) the built-in provider verifiers.

```bash
trufflehog filesystem --verifier https://verify.internal/check \
  --results verified --json /workspace > custom_verified.jsonl
```

The endpoint contract:
- Receives a POST with the matched secret payload.
- Returns a JSON response indicating `verified`, `unverified`, or `unknown`.
- Must respond within `--detector-timeout` or the result falls to `unknown`.

`--custom-verifiers-only` disables all built-in verifiers — only your endpoints are used. This is appropriate when:
- The secrets are for internal services with no public verification API.
- Built-in verifiers would generate unwanted traffic to external providers.
- The engagement restricts verification to an internal scope.

Security: your verification endpoint receives raw secrets. Host it on a trusted, access-controlled endpoint. Log minimally. Do not persist the secrets beyond the verification check.

---

## Configuration File

`--config <file>` loads a YAML/JSON configuration that can define:
- **Custom detectors**: regex patterns with optional verification endpoints.
- **Allowlists**: patterns to suppress (equivalent to gitleaks' allowlist in TOML, but in trufflehog's format).
- **Detector selection**: include/exclude detectors without CLI flags.
- **Multi-scan sources**: multiple source definitions for `multi-scan`.

```bash
trufflehog filesystem --config custom-config.yaml \
  --results verified,unverified --json /workspace > configured.jsonl
```

The config file is the right place for engagement-specific tuning that would otherwise require long CLI flag lists. Commit it alongside gitleaks' `.gitleaks.toml` in the assessment repo for reproducibility.

---

## Detector Performance Tuning

On large repos or org-wide scans, trufflehog's default concurrency may be too conservative or too aggressive.

- `--concurrency <n>` — worker goroutines. Raise for throughput on large targets; lower when verification traffic is rate-limited by providers.
- `--detector-timeout <dur>` — per-detector per-chunk timeout (e.g. `10s`, `30s`). Prevents a single slow verifier from blocking the scan. Default is generous — tighten for automation.
- `--print-avg-detector-time` — after the scan, prints average time per detector type. Use this to identify bottleneck detectors, then exclude them with `--exclude-detectors` if they're not relevant to the engagement.

```bash
trufflehog git https://github.com/org/large-mono \
  --concurrency 20 --detector-timeout 10s \
  --print-avg-detector-time \
  --results verified,unverified --json --no-update > mono.jsonl
# After: check which detectors are slow, exclude if irrelevant
```

---

## Archive and Binary Handling

- `--archive-max-size <size>` — skip archives larger than this (e.g. `4MB`, `512KB`). Prevents decompression bombs from consuming memory.
- `--archive-max-depth <n>` — recursion depth for nested archives (zip-in-zip). `0` disables archive scanning entirely.
- `--archive-timeout <dur>` — max time extracting a single archive. Prevents hangs on crafted or corrupted archives.
- `--force-skip-binaries` — hard-skip all binary files. Use when the target is source-only and binary scanning is wasted time.
- `--force-skip-archives` — hard-skip all archive files. Use when nested archives are not in scope.

Reasonable defaults for automation:
```bash
trufflehog filesystem \
  --archive-max-size 10MB --archive-max-depth 2 --archive-timeout 30s \
  --results verified --json --no-update /workspace > fs.jsonl
```

---

## Tool Chaining

- **gitleaks** (`tooling/gitleaks.md`): the shared git-history and filesystem secret-scanning workflow lives there. Run gitleaks for bulk pattern matching on git history; run trufflehog when you need live verification, remote sources, or Docker layer scanning.
- **trivy** (`tooling/trivy.md`): `trivy fs --scanners secret` overlaps with trufflehog's filesystem mode but has a narrower rule set. Use trivy when you're already scanning for vulns/misconfigs and want basic secret detection; use trufflehog when secrets are the primary target.
- **bandit** (`tooling/bandit.md`): bandit's B105–B107 find hardcoded credentials in Python source; trufflehog finds secrets across all file types and verifies them live.
- **nuclei** (`tooling/nuclei.md`): trufflehog finds exposed API keys → nuclei templates can validate what those keys grant access to (e.g. `http/exposures/tokens/`).
- **jwt_tool** (`tooling/jwt_tool.md`): `--drop-unverified-jwt-results` controls JWT noise in trufflehog output; for deep JWT analysis, pipe discovered JWTs to jwt_tool.

Pipeline — verified secrets with gitleaks cross-reference:
```bash
gitleaks git --report-format json --report-path gitleaks.json --redact /workspace
trufflehog git file:///workspace --results verified --json --no-update > trufflehog_verified.jsonl
# gitleaks: broad pattern coverage; trufflehog: live verification of what's still active
```

---

If uncertain, query web_search with:
`site:github.com/trufflesecurity/trufflehog trufflehog <flag>` or `site:docs.trufflesecurity.com`

Routed consumers:
- `vulnerabilities/information_disclosure.md` (secret-leak class — pair with gitleaks for coverage)
- `coordination/source_aware_whitebox.md`, `custom/source_aware_sast.md` (whitebox pipelines)
- `tooling/gitleaks.md` (the shared workflow lives there)
- `tooling/trivy.md` (`trivy fs --scanners secret` — narrower rules, use trufflehog for depth)
- `tooling/jwt_tool.md` (JWT-specific analysis after trufflehog discovery)
