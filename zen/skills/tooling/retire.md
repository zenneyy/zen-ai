---
name: retire
description: retire.js JavaScript/node dependency scanning — version detection, output formats, and severity gating for JS SCA.
---

# retire CLI Playbook

Official docs:
- https://retirejs.github.io/retire.js/
- https://github.com/RetireJS/retire.js

Canonical syntax:
`retire [options]`

High-signal flags:
- `--path <path>` folder to scan for JavaScript / node project files
- `-v, --verbose` show every scanned file (default output is vulnerable-only)
- `-c, --nocache` do not use the local jsrepo cache
- `--cachedir <path>` custom cache dir (default `/tmp/.retire-cache`)
- `--jsrepo <path|url>` custom JS vulnerability database (or `central` default); comma-separated for multiple
- `--outputformat <fmt>` output format: `text`, `json`, `jsonsimple`, `depcheck` (experimental), `cyclonedx`, `cyclonedxJSON`, `cyclonedxJSON1_6`, `cyclonedxJSON1_6_VEX`, `cyclonedxJSON1_7`, `cyclonedxJSON1_7_VEX`
- `--outputpath <file>` write to file
- `--ignore <paths>` comma-delimited paths to ignore
- `--ignorefile <file>` custom ignore file (defaults: `.retireignore` / `.retireignore.json`)
- `--severity <low|medium|high|critical|none>` severity floor at which the process fails
- `--exitwith <code>` custom non-zero exit (default `13`) when vulns found
- `--ext <extensions>` comma-separated JS extensions (default `js`)
- `--colors` enable color output (console only)
- `--insecure` fetch remote `--jsrepo` over bad/self-signed TLS
- `--cacert <file>` custom CA for remote jsrepo fetches
- `--includeOsv` include OSV advisories in the output
- `--deep` deep scan (slower; experimental — scans minified bundles more aggressively)
- `--proxy <url>` outbound proxy

Agent-safe baseline for automation:
`retire --path /workspace --outputformat json --outputpath retire.json --severity high --exitwith 0`

Common patterns:
- Default scan of a node/web project:
  `retire --path /workspace`
- JSON output for pipeline consumers:
  `retire --path /workspace --outputformat json --outputpath retire.json`
- CycloneDX SBOM output (feeds supply-chain SBOM pipelines):
  `retire --path /workspace --outputformat cyclonedxJSON1_6 --outputpath retire.cdx.json`
- High-severity only, don't fail CI:
  `retire --path /workspace --severity high --exitwith 0 --outputformat json --outputpath retire.json`
- Include OSV advisories (coverage beyond retire's own DB):
  `retire --path /workspace --includeOsv --outputformat json --outputpath retire.json`
- Deep scan on minified bundles (slower, catches more version strings):
  `retire --path /workspace --deep --outputformat json --outputpath retire_deep.json`
- Scan with a custom ignore file:
  `retire --path /workspace --ignorefile .retireignore.json --outputformat json --outputpath retire.json`
- Alternate extensions (`.mjs`, `.cjs`):
  `retire --path /workspace --ext js,mjs,cjs --outputformat json --outputpath retire.json`

## Detection Methodology

retire identifies vulnerable libraries through two independent channels:

1. **Lockfile / manifest scan:** reads `package.json`, `package-lock.json`, `yarn.lock`, and `pnpm-lock.yaml` to resolve declared dependency versions against the vulnerability database.
2. **JS file fingerprinting:** scans `.js` files (and `--ext` extensions) on disk for version strings, comment headers, and content hashes that match known library signatures. This catches CDN-copied, vendored, or bundled libraries that lockfiles don't know about.

Both channels run on every scan. `--deep` makes fingerprinting more aggressive on minified/webpack bundles by expanding the heuristic surface (slower, experimental).

## Suppression Files

retire honors `.retireignore` (line-based) and `.retireignore.json` (structured) at the scan root. `--ignorefile <path>` overrides the default location. `.retireignore.json` takes precedence when both exist.

`.retireignore.json` structure:
```json
[
  {
    "component": "jquery",
    "version": "3.3.1",
    "identifiers": { "issue": "https://github.com/nicedoc/issue/1234" },
    "justification": "XSS vector not reachable in our usage"
  }
]
```

Each entry suppresses findings for the matching component+version pair. `identifiers` and `justification` are advisory metadata for audit trails — retire does not enforce them.

Plain `.retireignore` is one path per line (glob patterns, same shape as `--ignore`).

## CycloneDX and VEX Output

retire produces six CycloneDX variants:
- `cyclonedx` / `cyclonedxJSON` — BOM-only (component inventory + known vulnerabilities)
- `cyclonedxJSON1_6` / `cyclonedxJSON1_7` — spec-version-pinned BOM
- `cyclonedxJSON1_6_VEX` / `cyclonedxJSON1_7_VEX` — BOM + VEX (Vulnerability Exploitability eXchange) statements

Use VEX variants when the downstream consumer (Dependency-Track, GUAC, or a compliance pipeline) needs exploitability assertions alongside the SBOM. Use plain CycloneDX when only the component inventory matters.

Critical correctness rules:
- Default exit code on findings is `13` (not `1`) — automation that expects `1` must set `--exitwith 1` or branch on `13`.
- `--severity high` is a hard **gate**: the process fails only on `high+` findings but still reports lower severities in the output.
- `--deep` significantly slows scans on large bundles; use it only when regular mode misses something you suspect.
- Default DB is `central` (retirejs's curated signatures); add `--includeOsv` for broader CVE coverage. For offline runs, pre-fetch `--jsrepo` locally.
- `.retireignore.json` wins over `.retireignore`; both are respected automatically from the scan root unless `--ignorefile` points elsewhere.
- `--outputpath` without `--outputformat` writes the default text format — always set both for machine-readable output.

Usage rules:
- Reach for retire as the JS/node counterpart to `trivy`'s SCA — trivy handles OS + many lockfiles well, retire catches JS-specific library fingerprints trivy misses.
- Use CycloneDX output when the pipeline expects SBOMs; otherwise JSON for jq consumers.
- Keep `--exitwith 0` on in agent automation (so downstream parsing runs); use the default `13` in gating pipelines.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- No findings on code you expect vulnerable libraries in: verify `--path`, check if vendored JS is in `.gitignore` (retire doesn't honor it, but your copy may skip it), run with `-v` to see what was scanned, try `--deep`.
- All findings suppressed: `.retireignore[.json]` may be too broad — print it and audit.
- Fetching the central DB fails: use `--jsrepo` with a mirror or offline file, or `--insecure` on self-signed TLS (sandbox has a Testing Root CA for Caido inspection).
- Non-zero exit breaks the pipeline unexpectedly: set `--exitwith 0` for scan-report-only runs.

If uncertain, query web_search with:
`site:retirejs.github.io retire <flag>` or `site:github.com/RetireJS/retire.js`

retire is a single-purpose JS/Node scanner with a flat flag surface; the above covers its full CLI capability. Depth for JS SCA workflows — prioritization, triage, remediation chaining — lives in `supply_chain/dependency_cve_scanning.md`.

Routed consumers:
- `supply_chain/dependency_cve_scanning.md` (JS/node SCA counterpart to the trivy workflow)
- `tooling/trivy.md` (OS + lockfile SCA; use both for full-stack coverage)
- `tooling/vulnx.md` (enrich retire's CVE IDs with KEV/PoC/template signals)
- `custom/source_aware_sast.md`, `coordination/source_aware_whitebox.md` (whitebox pipelines on JS-heavy projects)
