---
name: ssrf
description: SSRF testing for cloud metadata access, internal service discovery, and protocol smuggling
---

# SSRF

Server-Side Request Forgery enables the server to reach networks and services the attacker cannot. Focus on cloud metadata endpoints, service meshes, Kubernetes, and protocol abuse to turn a single fetch into credentials, lateral movement, and sometimes RCE.

## Attack Surface

**Scope**
- Outbound HTTP/HTTPS fetchers (proxies, previewers, importers, webhook testers)
- Non-HTTP protocols via URL handlers (gopher, dict, file, ftp, smb wrappers)
- Service-to-service hops through gateways and sidecars (envoy/nginx)
- Cloud and platform metadata endpoints, instance services, and control planes

**Direct URL Params**
- `url=`, `link=`, `fetch=`, `src=`, `webhook=`, `avatar=`, `image=`

**Indirect Sources**
- Open Graph/link previews, PDF/image renderers
- Server-side analytics (Referer trackers), import/export jobs
- Webhooks/callback verifiers

**Protocol-Translating Services**
- PDF via wkhtmltopdf/Chrome headless, image pipelines
- Document parsers, SSO validators, archive expanders

**Less Obvious**
- GraphQL resolvers that fetch by URL
- Background crawlers, repository/package managers (git, npm, pip)
- Calendar (ICS) fetchers

## High-Value Targets

### AWS

- IMDSv1: `http://169.254.169.254/latest/meta-data/` → `/iam/security-credentials/{role}`, `/user-data`
- IMDSv2: requires token via PUT `/latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then include `X-aws-ec2-metadata-token` on subsequent GETs
- If sink cannot set headers or methods, seek intermediaries that can
- ECS/EKS task credentials: `http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`
- **IMDSv2 hop-limit nuance**: the token response carries a PUT-response hop
  limit (default **1**) so the credential can't be relayed off-box. But
  containers add a hop, so a pod/container SSRF often *cannot* reach IMDSv2
  unless the instance was set to hop limit **≥2** (a common EKS/ECS
  misconfiguration) — if your container SSRF gets a token, note the hop limit as
  the root cause. IMDSv2 also needs both a `PUT` and a custom header, so a
  GET-only or header-less sink is stuck on v1-only instances; a sink that
  follows redirects or does CRLF header injection can sometimes supply them.

### GCP

- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Required header: `Metadata-Flavor: Google`
- Target: `/instance/service-accounts/default/token`

### Azure

- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Required header: `Metadata: true`
- MSI OAuth: `/metadata/identity/oauth2/token`

### Oracle Cloud (OCI)

- Endpoint: `http://169.254.169.254/opc/v2/instance/`
- v2 requires header `Authorization: Bearer Oracle`; v1 (`/opc/v1/instance/`) needs no header (deprecated but still enabled on older instances)
- Instance-principal material and metadata under `/opc/v2/instance/`; region/compartment/OCID in the JSON

### Alibaba Cloud

- Endpoint: `http://100.100.100.200/latest/meta-data/` (note the non-standard IP)
- RAM-role credentials: `/latest/meta-data/ram/security-credentials/<role-name>` → temporary AK/SK/token
- No auth header required by default

### DigitalOcean

- Endpoint: `http://169.254.169.254/metadata/v1/` (or `/metadata/v1.json`)
- No cloud-API credentials by default, but `/metadata/v1/user-data` frequently holds provisioning scripts with secrets, and SSH keys / region / tags leak
- No auth header required

### Kubernetes

- Kubelet: 10250 (authenticated) and 10255 (deprecated read-only)
- Probe `/pods`, `/metrics`, exec/attach endpoints
- API server: `https://kubernetes.default.svc/`
- Authorization often needs service account token; SSRF that propagates headers/cookies may reuse them
- Service discovery: attempt cluster DNS names (`svc.cluster.local`) and default services (kube-dns, metrics-server)

### Internal Services

- Docker API: `http://localhost:2375/v1.24/containers/json` (no TLS variants often internal-only)
- Redis/Memcached: `dict://localhost:11211/stat`, gopher payloads to Redis on 6379
- Elasticsearch/OpenSearch: `http://localhost:9200/_cat/indices`
- Message brokers/admin UIs: RabbitMQ, Kafka REST, Celery/Flower, Jenkins crumb APIs
- FastCGI/PHP-FPM: `gopher://localhost:9000/` (craft records for file write/exec when app routes to FPM)

## Key Vulnerabilities

### Protocol Exploitation

**Gopher**
- Speak raw text protocols (Redis/SMTP/IMAP/HTTP/FCGI)
- Use to craft multi-line payloads, schedule cron via Redis, or build FastCGI requests

`gopher://host:port/_<data>` sends `<data>` as a raw TCP stream after the
leading `_`, with CRLFs URL-encoded as `%0d%0a` — that lets you speak any
line-based protocol through an SSRF. The exact bytes are fiddly (RESP framing,
FastCGI records); generate them with **Gopherus** (`gopherus --exploit redis` /
`--exploit fastcgi`) rather than hand-rolling, then paste the produced
`gopher://...` URL into the sink. The canonical chains:
- **Redis** (`:6379`, unauth) → three RCE writes: set `dir`+`dbfilename` to
  drop a **cron** entry in `/var/spool/cron/`, an **authorized_keys** in a
  home dir, or a **webshell** into the webroot; or `MODULE LOAD` a malicious
  `.so`. Structure (Gopherus-encoded): `gopher://127.0.0.1:6379/_` + the RESP
  for `flushall`/`config set dir ...`/`set ...`/`save`.
- **FastCGI/PHP-FPM** (`:9000`) → craft a FastCGI record setting
  `PHP_VALUE=auto_prepend_file=php://input` (or `allow_url_include`) with your
  PHP in the body → RCE, even when no PHP file is web-reachable.
- **SMTP/other** → send mail, hit internal admin sockets, or any
  newline-delimited protocol the target port speaks.
Requires a curl-backed (or otherwise gopher-capable) sink — see Per-HTTP-Client
Behavior; a `requests`/Go/Node fetcher will reject `gopher://`.

**File and Wrappers**
- `file:///etc/passwd`, `file:///proc/self/environ` when libraries allow file handlers
- `jar:`, `netdoc:`, `smb://` and language-specific wrappers (`php://`, `expect://`) where enabled

### Address Variants

- Loopback: `127.0.0.1`, `127.1`, `2130706433`, `0x7f000001`, `::1`, `[::ffff:127.0.0.1]`
- RFC1918/link-local: 10/8, 172.16/12, 192.168/16, 169.254/16
- Test IPv6-mapped and mixed-notation forms

**Which alternate forms actually connect is client-dependent** — the fetcher's
resolver decides, not the filter. Measured (local listener on `127.0.0.1`,
clients: curl 8, wget, Python `requests`/`urllib`, Node 24 `fetch`/undici, Go
1.26 `net/http`):

| Form (→127.0.0.1) | curl | wget | Python | Node | Go `net/http` |
|---|---|---|---|---|---|
| `127.1` (short) | Y | Y | Y | Y | **no** |
| `2130706433` (decimal) | Y | Y | Y | Y | **no** |
| `0x7f000001` (hex) | Y | Y | Y | Y | **no** |
| `0177.0.0.1` (octal) | Y | Y | Y | Y | **no** |
| `0` (→0.0.0.0) | Y | Y | Y | Y | **no** |
| `localhost` / `127.0.0.1` | Y | Y | Y | Y | Y |

The takeaway: curl, wget, Python, and Node all route these legacy forms through
`getaddrinfo`, so decimal/hex/octal/`http://0` **bypass a filter that only
blocks the literal `127.0.0.1`/`localhost` strings**. **Go's `net/http` is the
outlier — it rejects every alternate numeric form**, so against a Go fetcher
those payloads fail and you need a real dotted IP, a hostname, or DNS
rebinding. Fingerprint the fetcher (`Server`, timing, error strings, TLS stack)
and pick forms its resolver accepts. `[::1]`/`[::ffff:127.0.0.1]` reach only a
service **bound to IPv6 loopback** — a miss there is a binding fact, not a
parsing one; retry the IPv4 forms.

### Per-HTTP-Client Behavior

Two more client-decided properties, measured the same way (Java from documented
behavior):

- **Default redirect following** (the filter checks the initial allowlisted URL,
  the client follows a `302` to an internal host): **curl does *not* follow by
  default** (needs `-L`); **wget, Python `requests`/`urllib`, Node `fetch`, and
  Go `net/http` all follow by default** (measured). Java `HttpURLConnection`
  follows by default; Java 11+ `HttpClient` does **not** (`Redirect.NEVER`
  default). So a redirect-to-internal bypass works out of the box against most
  stacks but not a bare curl or the newer Java client — confirm by pointing an
  allowlisted host at a `302 Location: http://169.254.169.254/...`.
- **Non-HTTP scheme support**: **curl** speaks `gopher:`, `dict:`, `file:`,
  `ftp:`, `ldap:`, `tftp:` — the widest protocol reach and the one to hope for
  behind an SSRF (gopher → Redis/FCGI below). **wget** does HTTP(S)/FTP only;
  **Python `urllib`** handles `file:`/`ftp:` (and `data:`); **`requests`,
  Node `fetch`, Go `http.Get`** are HTTP(S)-only unless the app wired a custom
  handler. If the sink is a curl wrapper, always test `gopher://` and `file://`.

### URL Confusion

- Userinfo and fragments: `http://internal@attacker/` or `http://attacker#@internal/`
- Scheme-less/relative forms the server might complete internally: `//169.254.169.254/`
- Trailing dots and mixed case: `internal.` vs `INTERNAL`, Unicode dot lookalikes

### Redirect Abuse

- Allowlist only applied pre-redirect: 302 from attacker → internal host
- Test multi-hop and protocol switches (http→file/gopher via custom clients)

### Header and Method Control

- Some sinks reflect or allow CRLF-injection into the request line/headers
- If arbitrary headers/methods are possible, IMDSv2, GCP, and Azure become reachable

## Bypass Techniques

**Address Encoding**
- Decimal, hex, octal representations of IP addresses
- IPv6 variants, IPv4-mapped IPv6, mixed notation

**DNS Rebinding**
- First resolution returns allowed IP, second returns internal target
- Use short TTL DNS records under attacker control
- The precondition is a **check-then-fetch gap**: the app resolves your
  hostname, validates the returned IP against the allowlist (passes, points at
  a public/attacker IP), then resolves *again* at fetch time (now returns
  `169.254.169.254`/`127.0.0.1`). Anything that caches the first resolution and
  connects to that exact IP is immune; the vulnerable pattern re-resolves.
- **Singularity of Origin** (NCC Group) is the standard framework — it runs the
  authoritative DNS that flips the answer and the manager UI/timing to win the
  rebind; `rbndr` (a public rebinding service) alternates two fixed IPs by
  hostname for quick manual tests. Set the TTL to 0/1 and, for slow caches,
  use the multiple-A-record / flooding modes.
- Prefer rebinding when the sink resolves hostnames but blocks literal IPs, or
  when a Go/newer-Java fetcher rejected your numeric-form payloads (above).

**URL Parser Differentials**
- Different parsing between allowlist checker and actual fetcher
- Exploit inconsistencies in scheme, host, port, path handling

**Redirect Chains**
- Initial URL passes allowlist, redirect targets internal host
- Protocol downgrade/upgrade through redirects

## Blind SSRF

- Use OAST (DNS/HTTP) to confirm egress. `interactsh-client -v` (running
  in the sandbox) gives you a unique `*.oast.fun` domain; embed it in
  the URL parameter and watch the interactsh stdout for the inbound
  DNS/HTTP hit. Each invocation yields a fresh domain — restart between
  payloads if you need to correlate hits to a specific request.
- Derive internal reachability from timing, response size, TLS errors, and ETag differences
- Build a port map by binary searching timeouts (short connect/read timeouts yield cleaner diffs)

## Chaining Attacks

- SSRF → Metadata creds → cloud API access (list buckets, read secrets)
- SSRF → Redis/FCGI/Docker → file write/command execution → shell
- SSRF → Kubelet/API → pod list/logs → token/secret discovery → lateral movement

## Testing Methodology

1. **Identify surfaces** - Every user-influenced URL/host/path across web/mobile/API and background jobs
2. **Establish oracle** - Quiet OAST DNS/HTTP callbacks first
3. **Internal addressing** - Pivot to loopback, RFC1918, link-local, IPv6, hostnames
4. **Protocol variations** - Test gopher, file, dict where supported
5. **Parser differentials** - Test across frameworks, CDNs, and language libraries
6. **Redirect behavior** - Single-hop, multi-hop, protocol switches
7. **Header/method control** - Can you influence request headers or HTTP method?
8. **High-value targets** - Metadata, kubelet, Redis, FastCGI, Docker, Vault, internal admin panels

## Validation

1. Prove an outbound server-initiated request occurred (OAST interaction or internal-only response differences)
2. Show access to non-public resources (metadata, internal admin, service ports) from the vulnerable service
3. Where possible, demonstrate minimal-impact credential access (short-lived token) or a harmless internal data read
4. Confirm reproducibility and document request parameters that control scheme/host/headers/method and redirect behavior

## False Positives

- Client-side fetches only (no server request)
- Strict allowlists with DNS pinning and no redirect following
- SSRF simulators/mocks returning canned responses without real egress
- Blocked egress confirmed by uniform errors across all targets and protocols
- OAST callbacks where the source IP matches the tester's machine, not the server — the browser or a client-side fetch made the request, not the backend

## Impact

- Cloud credential disclosure with subsequent control-plane/API access
- Access to internal control panels and data stores not exposed publicly
- Lateral movement into Kubernetes, service meshes, and CI/CD
- RCE via protocol abuse (FCGI, Redis), Docker daemon access, or scriptable admin interfaces

## Pro Tips

1. Prefer OAST callbacks first; then iterate on internal addressing and protocols
2. Test IPv6 and mixed-notation addresses; filters often ignore them
3. Observe library/client differences (curl, Java HttpClient, Node, Go); behavior changes across services and jobs
4. Redirects are leverage: control both the initial allowlisted host and the next hop
5. Metadata endpoints require headers/methods; verify if your sink can set them or if intermediaries add them
6. Use tiny payloads and tight timeouts to map ports with minimal noise
7. When responses are masked, diff length/ETag/status and TLS error classes to infer reachability
8. Chain quickly to durable impact (short-lived tokens, harmless internal reads) and stop there

## Summary

Any feature that fetches remote content on behalf of a user is a potential tunnel to internal networks and control planes. Bind scheme/host/port/headers explicitly or expect an attacker to route through them.
