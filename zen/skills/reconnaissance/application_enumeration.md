---
name: application-enumeration
description: Application-level reconnaissance for live web targets covering route discovery, parameter enumeration, authenticated surface mapping, JavaScript bundle mining, multi-service architecture detection, and recon-completeness discipline before hunter scoping
---

# Application Enumeration

Once a live target URL is known, the job shifts from finding hosts to mapping what is inside one. Application enumeration is the systematic discovery of every route, parameter, authenticated view, config artifact, and internal service a single application exposes — the surface a hunter agent will actually test. External asset discovery (finding the org's hosts and domains) is the sibling skill `asset_discovery`; this skill starts where that one ends, from a reachable URL, and produces the enumerated surface that hunter scoping depends on.

Run this to completion before scoping hunter agents to specific vulnerability classes. A hunter scoped to the obvious surface misses the endpoints that live only in a JS bundle, the parameters the app never puts in a form, the views that appear only after login, and the internal services reachable only by chaining. The output is a route + parameter + auth-surface + service inventory with a defined completeness bar, not a crawl of the landing page.

Three topic-focused deep siblings expand this file and load automatically in deep scan mode: `application_enumeration_api_deep` (REST/GraphQL/gRPC/tRPC/WebSocket/WebRTC API-surface depth), `application_enumeration_client_deep` (client-side and JS-ecosystem depth — Web/Service Workers, WebAssembly, module federation, source-map reconstruction), and `application_enumeration_auth_multiservice_deep` (authenticated-surface depth — OAuth/OIDC/SAML/WebAuthn — multi-tenant/multi-service architecture, and AI/ML endpoints). In standard mode this base file is enough.

## Attack Surface

- **Route surface** — routing tables, URL patterns, sitemap- and robots-declared paths, framework route manifests, archived/deprecated routes still served
- **Parameter surface** — GET/POST params, JSON body fields, headers the app reads, GraphQL variables, hidden and rarely-used inputs
- **Authenticated surface** — post-login views and per-role differences; the endpoints and parameters that only exist inside a session
- **File and content surface** — config exposure, backup files, DVCS metadata, source maps, API documentation
- **Multi-service architecture** — internal-only services reachable from a public-facing one via network links or an SSRF/RCE chain

## High-Value Targets

Prioritize discovering:

- Framework config files: `.env`, `application.properties`, `appsettings.json`, `settings.py`, `next.config.js`, `nuxt.config.js`
- API documentation exposure: `/swagger`, `/openapi.json`, `/api-docs`, and `/graphql` with introspection enabled
- Admin and debug surfaces: `/actuator` (especially `/actuator/env`, `/actuator/heapdump`), `/admin`, `/console`, `/manager/html`
- Authenticated views that differ from the unauthenticated ones — the delta is where authorization is actually enforced, or not
- Internal-only services reachable via an SSRF chain from the public app
- DVCS exposure (`/.git/`) enabling full source reconstruction

## Reconnaissance

### Route and Endpoint Discovery

Start with what the app declares, then brute-force, then mine archives:

```bash
curl -s <target>/robots.txt; curl -s <target>/sitemap.xml
curl -s <target>/.well-known/security.txt
katana -u <target> -jc -kf all -d 3 -o routes.txt          # crawl incl. JS-parsed links
feroxbuster -u <target> -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
ffuf -u <target>/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,204,301,302,401,403
```

Archive mining recovers routes that were deprecated but never removed from the server:

```bash
waybackurls <domain> | sort -u > wayback.txt
gau --threads 5 <domain> | sort -u >> wayback.txt
```

Framework route manifests are the fastest complete route list for SPAs:

- **Next.js** — `/_next/static/<build>/_buildManifest.js` and `_ssgManifest.js` list every page route the app ships
- **Angular / React / Vue** — router config is compiled into the main chunk; extract it from the bundle (below). Chunk filenames (`chunk-<hash>.js`, `main.<hash>.js`) map the module graph

In deep mode, per-API-technology enumeration (REST versions/methods, GraphQL introspection/federation, gRPC reflection, tRPC, WebSocket/SSE, WebRTC) is in `application_enumeration_api_deep`.

### JavaScript Bundle Mining

For any SPA the client-side code is the authoritative route and endpoint list — mine it before brute-forcing:

```bash
echo <target> | subjs | tee jsfiles.txt                    # collect every served .js URL
mkdir -p bundles; while read u; do curl -s "$u" -o "bundles/$(basename "$u")"; done < jsfiles.txt
linkfinder -i <target> -d -o cli                           # crawl the domain for JS, extract paths
jsluice urls bundles/*.js ; jsluice secrets bundles/*.js
```

Grep bundles directly for endpoint construction the extractors miss:

```bash
grep -RhoE '/(api|v[0-9]+|graphql|internal|admin)/[A-Za-z0-9_/.-]+' bundles/ | sort -u
grep -RhnE '(axios\.(get|post|put|delete)|fetch|XMLHttpRequest)\(' bundles/
```

Source maps expose the original module structure and internal API layout — check for them explicitly, they are frequently left in production:

```bash
while read u; do echo "$(curl -s -o /dev/null -w '%{http_code}' "$u.map") $u.map"; done < jsfiles.txt
```

A `200` means the source map is present. Load `information_disclosure` for the full source-map reconstruction workflow; this section covers detection.

In deep mode, deeper client-side mining (Web/Service Workers, WebAssembly, module federation, full source-map reconstruction) is in `application_enumeration_client_deep`.

### Parameter Discovery

Endpoints accept parameters the UI never shows. Enumerate them per endpoint:

```bash
arjun -u <target>/api/endpoint                             # GET params
arjun -u <target>/api/endpoint -m POST                     # POST body params
paramspider -d <domain>                                    # wayback-mined params
x8 -u <target>/api/endpoint -w params.txt                  # response-differential fuzzing
```

Pull parameters from the bundles too: `grep -RhnE 'params\.append|URLSearchParams|name=' bundles/`. Then systematically test this catalog on JSON APIs even when undocumented — each maps to an authorization or logic boundary:

```
id  user_id  account_id  tenant_id  org_id  role  is_admin  debug  test
include_deleted  as_user  impersonate  override_*  _method  next  redirect
return_to  callback  webhook  url  file  path
```

### Content and Config Discovery

Probe for config, DVCS, backups, and management surfaces:

```bash
# framework config
ffuf -u <target>/FUZZ -mc 200 -w <(printf '%s\n' .env .env.local .env.production \
  config.php settings.py application.properties appsettings.json next.config.js nuxt.config.js)
# DVCS exposure — any 200 means source reconstruction is possible
for p in .git/HEAD .git/config .svn/entries .hg/requires .bzr/branch-format; do
  echo "$(curl -s -o /dev/null -w '%{http_code}' <target>/$p) $p"; done
git-dumper http://<target>/.git/ ./dumped                  # when /.git/ responds
# backup suffixes on a discovered file
for s in .bak .old .orig '~' .swp; do
  echo "$(curl -s -o /dev/null -w '%{http_code}' "<target>/<file>$s") $s"; done
```

Debug/admin and API-doc surfaces to probe directly: `/actuator`, `/actuator/env`, `/actuator/heapdump`, `/debug`, `/admin`, `/wp-admin`, `/manager/html`, `/console`, `/_ah/admin`, `/swagger`, `/swagger.json`, `/openapi.json`, `/redoc`. Test GraphQL introspection:

```bash
curl -s <target>/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

### Authenticated Recon

Unauthenticated recon sees a fraction of the app. Once you can authenticate:

- **Re-run every route and parameter pass under the authenticated session.** Most SPA endpoints only appear in bundles served post-login, and many parameters are accepted only with a valid session.
- **Enumerate per role.** Authenticate as each available role (user, moderator, admin, staff, service account) and diff the accessible surfaces. Role differentials expose the authorization boundaries to test before hunting IDOR/BFLA — load `broken_function_level_authorization` for that hunt.
- **Multi-tenant diff.** Authenticate into two tenants and diff surfaces to spot tenant-scoping gaps at recon time.

In deep mode, authenticated-surface depth (OAuth/OIDC/SAML/WebAuthn), multi-tenant/multi-service architecture, and AI/ML endpoint enumeration are in `application_enumeration_auth_multiservice_deep`.

### Multi-Service Architecture Detection

**Source available** — parse the deployment manifests for the internal service graph:

```bash
yq '.services | to_entries[] | {name:.key, ports:.value.ports, deps:.value.depends_on}' docker-compose.yml
grep -RhnE 'ClusterIP|LoadBalancer|NodePort|containerPort|- port:' kubernetes/ k8s/ helm/
```

- A service in `docker-compose.yml` with **no top-level `ports:` mapping** is reachable only from other services on that network — a prime SSRF-chain target, not an externally reachable host.
- Kubernetes `type: ClusterIP` is internal-only; `LoadBalancer`/`NodePort` are externally reachable. Internal DNS is `<service>.<namespace>.svc.cluster.local`.
- Istio/Linkerd sidecar containers indicate a service mesh — internal routing and mTLS change what a chain can reach (load `kubernetes`).

**Source not available** — from any SSRF primitive, probe the common internal service ports and catalog what answers:

```
3306 5432 6379 9200 27017 2375 8080 8081 8443 9090
```

Every internal-only service becomes an SSRF-chain candidate — load `ssrf` for the chain primitives.

### JavaScript Static Analysis for Secrets

Bundles routinely ship credentials and internal URLs:

```bash
trufflehog filesystem bundles/ --json --no-verification
secretfinder -i <target> -o cli
```

Look for `.js.map` files (above) and Vite/Webpack build info (`__webpack_require__` chunk lists, `manifest.json`) that leak internal structure. This is detection only; load `information_disclosure` for the reconstruction and impact workflow.

## Completeness Criteria

Recon is done only when all of the following hold:

- Every discovered host has had its route surface enumerated (sitemap + JS bundles + directory brute-force + archive mining)
- Every discovered endpoint has had its parameter surface enumerated (arjun / paramspider / x8, or bundle extraction)
- If authentication is available, the authenticated surface has been re-enumerated for **each** accessible role
- If source is available, every `docker-compose.yml`, `kubernetes/**`, and `helm/**` manifest has been parsed for services and ports
- Internal service ports have been catalogued as SSRF-chain candidates
- Route enumeration has **plateaued** — another discovery pass yields no new endpoints

Only then should hunter agents be scoped. The orchestration side of this bar is in `root_agent`.

## Validation

Prove the enumeration did not miss surfaces:

- Diff the enumerated route list against the JS-bundle URL extraction — any bundle path absent from the route list was missed
- Check `robots.txt` `Disallow:` entries for paths not in the enumerated set
- Compare authenticated vs unauthenticated route lists — the authenticated list should be larger; if it is not, authenticated recon was incomplete
- Source-aware: cross-reference route declarations (`urls.py`, `routes.rb`, `next.config.js`, controller annotations) against the enumerated list

## Tooling

- **Route discovery**: `katana`, `ffuf`, `feroxbuster`, `hakrawler`, `gospider`
- **JS analysis**: `subjs`, `LinkFinder`, `jsluice`, `xnLinkFinder`, `SecretFinder`
- **Parameter discovery**: `arjun`, `paramspider`, `x8`
- **Archive mining**: `waybackurls`, `gau`, `waymore`
- **Source-aware / DVCS**: `git-dumper` (reconstruct from an exposed `/.git/`), `yq` (parse deployment manifests)
- **Secrets in bundles**: `trufflehog`, `SecretFinder`

Install any tool not present at runtime; the sandbox has `pip`, `go`, and `git`.

## Pro Tips

1. JS bundle mining beats directory brute-force for SPA targets — the app tells you every route it calls.
2. Always re-run enumeration after login; the authenticated surface is where the untested endpoints live.
3. Internal-only services in `docker-compose.yml` (no `ports:` mapping) are prime SSRF-chain targets — catalog them before scoping.
4. Wayback and `gau` find deprecated endpoints that were never deleted from the server.
5. If a `.js.map` exists, source reconstruction is often possible even without `/.git/` exposure.
6. Diff role-by-role authenticated surfaces at recon time — the deltas are your IDOR/BFLA test list, pre-computed.
7. Keep every stage's output on disk so route and parameter lists chain into the hunters you scope next.

## Summary

Application enumeration maps the inside of one live target — routes, parameters, authenticated views, config artifacts, and internal services — and is distinct from the external host discovery in `asset_discovery`. It must run to the completeness bar above before hunter agents are scoped, so that hunters test the full enumerated surface rather than the landing page.
