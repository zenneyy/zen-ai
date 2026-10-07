---
name: tlsx
description: tlsx TLS/certificate recon syntax, probe selection, misconfiguration flags, and CT-log streaming for cert-driven asset discovery.
---

# tlsx CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/tlsx/usage
- https://docs.projectdiscovery.io/opensource/tlsx/running
- https://github.com/projectdiscovery/tlsx

Canonical syntax:
`tlsx [flags]` (reads targets from `-u <host|csv>`, `-l <file>`, or stdin)

Install (not preinstalled in the sandbox):
`go install -v github.com/projectdiscovery/tlsx/cmd/tlsx@latest`
(installed to `$HOME/go/bin/tlsx`; sandbox PATH already includes it.)

## High-signal flags

Input:
- `-u, -host <host[,host]>` single/multi target
- `-l, -list <file>` targets file
- `-p, -port <port[,port]>` target port (default 443)

Scan mode:
- `-sm, -scan-mode <ctls|ztls|openssl|auto>` TLS stack (default `auto`)
- `-ps, -pre-handshake` ztls-based early-termination handshake
- `-sa, -scan-all-ips` scan every resolved IP for a hostname
- `-iv, -ip-version <4|6>` IP version (default 4)

Probes:
- `-san` subject alternative names
- `-cn` subject common name
- `-so` subject organization
- `-tv, -tls-version` negotiated TLS version
- `-cipher` negotiated cipher
- `-hash <md5|sha1|sha256>` certificate fingerprint
- `-jarm` JARM fingerprint
- `-ja3` / `-ja3s` JA3/JA3S (ztls mode only)
- `-wc, -wildcard-cert` host with wildcard cert
- `-tps, -probe-status` TLS probe status
- `-ve, -version-enum` enumerate supported TLS versions
- `-ce, -cipher-enum` enumerate supported ciphers
- `-ct, -cipher-type <all|secure|insecure|weak>` filter cipher enum (comma-separated, default all)
- `-ch, -client-hello` include client hello in JSON (ztls only)
- `-sh, -server-hello` include server hello in JSON (ztls only)
- `-se, -serial` cert serial number

Misconfigurations:
- `-ex, -expired` expired certificate
- `-ss, -self-signed` self-signed certificate
- `-mm, -mismatched` mismatched certificate (CN/SAN vs hostname)
- `-re, -revoked` revoked certificate (downloads full CRLs/OCSP per cert — high memory/network cost)
- `-un, -untrusted` untrusted certificate

Certificate Transparency:
- `-ctl, -ct-logs` stream CT logs
- `-cb, -ctl-beginning` start from index 0
- `-cti, -ctl-index <sourceID=index>` custom start per log

Config:
- `-config <file>` config file path
- `-r, -resolvers <file|list>` custom resolvers
- `-cc, -cacert <file>` client CA file
- `-ci, -cipher-input <list>` ciphers to use with TLS connection
- `-sni <host[,host]>` TLS SNI hostname(s)
- `-rs, -random-sni` use random SNI when empty
- `-rps, -rev-ptr-sni` reverse PTR to retrieve SNI from IP
- `-min-version <ssl30|tls10|tls11|tls12|tls13>` minimum TLS version
- `-max-version <ssl30|tls10|tls11|tls12|tls13>` maximum TLS version
- `-cert, -certificate` include cert PEM in JSON output
- `-tc, -tls-chain` include cert chain in JSON output
- `-vc, -verify-cert` verify server certificate
- `-ob, -openssl-binary <path>` OpenSSL binary path
- `-hf, -hardfail` treat revocation check errors as revoked (requires `-revoked`)
- `-proxy <socks5://host:port>` SOCKS5 proxy

Rate/optimization:
- `-c, -concurrency <n>` concurrent threads (default 300)
- `-cec, -cipher-concurrency <n>` cipher enum concurrency per target (default 10)
- `-timeout <sec>` TLS connection timeout (default 5)
- `-retry <n>` retries for failures (default 3)
- `-delay <dur>` wait between connections per thread (e.g. `200ms`, `1s`)

Output:
- `-o, -output <file>` output file
- `-j, -json` JSON format
- `-dns` unique hostnames extracted from cert
- `-ro, -resp-only` TLS response only
- `-silent` silent output
- `-nc, -no-color` disable color
- `-v, -verbose` verbose
- `-version` display version

Debug:
- `-health-check, -hc` diagnostic check

## Agent-safe baseline

```
tlsx -l hosts.txt -san -cn -tv -jarm -c 100 -timeout 5 -retry 2 -silent -j -o tlsx.jsonl
```

## Common patterns

SAN harvesting for asset discovery (most common use):
```
tlsx -l hosts.txt -san -cn -silent -j -o tlsx_san.jsonl
```

Flatten SANs into a unique hostname list (feeds dnsx/httpx):
```
tlsx -l hosts.txt -dns -silent -o tlsx_hosts.txt
```

Misconfiguration sweep (expired/self-signed/mismatched/untrusted):
```
tlsx -l hosts.txt -ex -ss -mm -un -silent -j -o tlsx_misconfig.jsonl
```

JARM fingerprint for server clustering/WAF identification:
```
tlsx -l hosts.txt -jarm -silent -j -o tlsx_jarm.jsonl
```

TLS version + cipher enumeration (weak-crypto audit):
```
tlsx -l hosts.txt -ve -ce -ct weak,insecure -silent -j -o tlsx_crypto.jsonl
```

CT-log stream (passive asset discovery via Certificate Transparency):
```
tlsx -ctl -silent -j -o tlsx_ctl.jsonl
```

Non-443 targets (SMTP/IMAP/custom):
```
tlsx -l hosts.txt -p 443,465,993,8443 -san -silent -j -o tlsx_multi.jsonl
```

Scan every resolved IP (certs behind geo-DNS):
```
tlsx -l hosts.txt -sa -san -silent -j -o tlsx_allips.jsonl
```

## Critical correctness rules

- `-san` + `-dns` are the asset-discovery pipeline: cert SANs become unique hostnames, which feed `dnsx` for resolution and `httpx` for live-check. Without `-san` you get nothing recon-interesting.
- `-sa` multiplies connection count by the number of resolved IPs per host; expensive on CDNs. Enable only when geo-DNS matters.
- `-re, -revoked` downloads full CRLs and makes OCSP calls per cert — slow, memory-heavy, and network-noisy. Off by default; enable only when revocation specifically matters.
- `-sm auto` is right in almost every case; use `-sm ztls` only for probes that require it (`-ja3`, `-ja3s`, `-ch`, `-sh`, `-ps`).
- `-ctl` is an **unbounded stream**; always combine with `-o <file>` plus a wall-clock cap or external timeout. Starting from `-cb` replays the entire CT history.
- `-vc` verifies against the sandbox trust store (`REQUESTS_CA_BUNDLE`); on `-ss`/`-mm`/`-un` passes you want this on.
- `-sni` overrides the TLS SNI sent — mandatory when probing an IP that serves multiple certs via SNI.
- `-ci` overrides the cipher suite list sent in the ClientHello — sending a non-default set changes the server's negotiated cipher and the resulting JA3 hash.
- `-hf` only works with `-re`; without `-revoked`, `-hardfail` has no effect.
- `-ct` filters cipher **enumeration** output (the `-ce` probe), not which ciphers the client offers during normal probes.

## Usage rules

- Pair with `tooling/dnsx.md` for the recon pipeline: `tlsx -san -dns | dnsx -silent | httpx -silent`.
- Keep `-silent -j -o <file>` on in automation; the default text output drops cert detail.
- Set `-timeout 5 -retry 2 -c 100` as the automation baseline; defaults (300 concurrency, 3 retries) can exhaust IP conntrack on constrained hosts.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

---

## Methodology

tlsx serves TLS/certificate intelligence across five distinct workflows: asset discovery (SAN harvesting + CT logs), cryptographic auditing (version/cipher enumeration), misconfiguration detection, server fingerprinting (JARM/JA3), and certificate chain analysis. Each workflow has a different flag set, target scope, and downstream consumer.

### Phase 1 — Asset discovery via SAN harvesting

The primary recon use. Certificate Subject Alternative Names list every hostname a cert covers — often including internal names, staging hosts, and related domains not visible through DNS or HTTP crawling.

Baseline SAN harvest:
```
tlsx -l hosts.txt -san -cn -so -silent -j -o tlsx_san.jsonl
```

Adding `-so` (subject organization) helps attribute certs to entities across acquisitions and shared infrastructure.

Flatten to a unique hostname list for downstream resolution:
```
tlsx -l hosts.txt -dns -silent -o tlsx_hostnames.txt
```

The `-dns` flag extracts unique hostnames from CN + SAN fields and deduplicates — purpose-built for piping into `dnsx` or `httpx`.

Multi-port SAN harvest for non-web TLS services:
```
tlsx -l hosts.txt -p 443,465,587,993,995,8443,9443 -san -cn -silent -j -o tlsx_multiport.jsonl
```

Ports 465 (SMTPS), 587 (SMTP/STARTTLS), 993 (IMAPS), 995 (POP3S) frequently serve certs with SANs not visible on port 443.

Per-IP SAN divergence (geo-DNS, CDN edge variation):
```
tlsx -l hosts.txt -sa -san -cn -silent -j -o tlsx_allip_san.jsonl
```

`-sa` resolves every A/AAAA record per host and connects to each IP separately. CDN-fronted hosts may serve different certs per edge node, exposing origin SANs.

### Phase 2 — Passive asset discovery via CT log streaming

CT logs are public, append-only ledgers of every certificate issued by participating CAs. Streaming them discovers domains without touching the target.

Live stream (current entries only):
```
tlsx -ctl -san -cn -silent -j -o tlsx_ct_live.jsonl
```

Historical replay from the beginning of each log:
```
timeout 600 tlsx -ctl -cb -san -cn -silent -j -o tlsx_ct_full.jsonl
```

Always wrap `-ctl -cb` with `timeout` — replaying from index 0 across all logs is unbounded and will fill disk.

Resume from a specific log index (tracked from prior runs):
```
tlsx -ctl -cti "google_xenon2025h2=500000" -san -cn -silent -j -o tlsx_ct_resume.jsonl
```

`-cti` takes `<sourceID>=<index>` pairs, allowing incremental CT monitoring. Track the last index per source ID in output JSONL and pass it back on the next run.

CT streaming is entirely passive — no connection to the target infrastructure. The data is fetched from CT log servers (Google Argon/Xenon, Cloudflare Nimbus, etc.). Useful when active scanning is prohibited or premature.

Filter CT output for a target domain downstream:
```
tlsx -ctl -san -cn -silent | grep -i "target\.tld" | sort -u > ct_target_subs.txt
```

### Phase 3 — TLS version and cipher auditing

Identifies hosts offering deprecated protocols (SSLv3, TLS 1.0, TLS 1.1) or weak/insecure cipher suites.

Full cipher enumeration:
```
tlsx -l hosts.txt -ve -ce -silent -j -o tlsx_full_crypto.jsonl
```

`-ve` enumerates all TLS versions the server accepts. `-ce` enumerates all cipher suites the server negotiates. Combined, this produces the complete negotiation surface.

Focused weak-crypto audit:
```
tlsx -l hosts.txt -ve -ce -ct weak,insecure -silent -j -o tlsx_weak_crypto.jsonl
```

`-ct weak,insecure` filters cipher enumeration output to only ciphers classified as weak or insecure. The server is still probed for all ciphers; the filter applies to output.

Cipher enumeration concurrency tuning:
```
tlsx -l hosts.txt -ce -cec 5 -c 50 -delay 500ms -silent -j -o tlsx_cipher_slow.jsonl
```

`-cec 10` (default) runs 10 parallel cipher probes per target. On rate-limited or fragile targets, lower `-cec` to 3-5 and add `-delay`. The effective connection count per target is `cec × (number of ciphers tested)`.

Version-constrained audit (only probe TLS 1.0/1.1):
```
tlsx -l hosts.txt -ve -min-version tls10 -max-version tls11 -silent -j -o tlsx_legacy.jsonl
```

If the server negotiates within this range, the host accepts deprecated protocols. Useful for compliance-scoped audits where only specific versions are in question.

### Phase 4 — Misconfiguration detection

Sweep for certificate-level issues across the host inventory.

Full misconfiguration pass:
```
tlsx -l hosts.txt -ex -ss -mm -un -vc -silent -j -o tlsx_misconfig.jsonl
```

`-vc` (verify-cert) validates the chain against the system trust store. Combined with `-ss` (self-signed), `-mm` (mismatched CN/SAN vs hostname), `-un` (untrusted root/intermediate), and `-ex` (expired), this catches the standard compliance failures.

Revocation check (expensive, targeted):
```
tlsx -l high_value_hosts.txt -re -hf -vc -silent -j -o tlsx_revoked.jsonl
```

`-re` downloads CRLs and queries OCSP for every certificate. `-hf` (hardfail) treats revocation check errors (network failure, OCSP timeout) as revoked. Run only on a narrow target list — CRL downloads are large and OCSP queries are per-cert.

Expired-cert-only check (lightweight):
```
tlsx -l hosts.txt -ex -silent -j -o tlsx_expired.jsonl
```

Wildcard certificate inventory:
```
tlsx -l hosts.txt -wc -san -cn -silent -j -o tlsx_wildcard.jsonl
```

`-wc` flags hosts serving wildcard certs (`*.target.tld`). Wildcard certs have broader blast radius on compromise — inventory them separately. The `-san` output shows the wildcard pattern alongside any additional SANs.

### Phase 5 — Server fingerprinting (JARM / JA3)

JARM fingerprinting:
```
tlsx -l hosts.txt -jarm -silent -j -o tlsx_jarm.jsonl
```

JARM sends 10 specially crafted TLS ClientHello messages and hashes the server responses into a 62-character fingerprint. Identical JARM hashes indicate identical TLS stack configuration — useful for:
- Grouping servers behind the same reverse proxy/load balancer
- Identifying WAF/CDN products (Cloudflare, Akamai, AWS ALB each produce distinctive JARMs)
- Detecting infrastructure shared across different domains
- Tracking C2 servers that share a TLS configuration

JARM with certificate probes for correlation:
```
tlsx -l hosts.txt -jarm -san -cn -so -tv -cipher -silent -j -o tlsx_jarm_full.jsonl
```

Correlating JARM with cert organization (`-so`), negotiated version (`-tv`), and cipher (`-cipher`) enables cluster analysis: same JARM + same org = shared infrastructure; same JARM + different org = shared hosting or CDN.

JA3/JA3S fingerprinting (requires ztls mode):
```
tlsx -l hosts.txt -ja3 -ja3s -sm ztls -silent -j -o tlsx_ja3.jsonl
```

`-ja3` captures the client's own JA3 hash as sent by tlsx (useful for understanding what fingerprint the scan itself presents). `-ja3s` captures the server's JA3S response hash. Both require `-sm ztls`.

Client/server hello extraction for deep analysis:
```
tlsx -u target.tld -ja3 -ja3s -ch -sh -sm ztls -j -o tlsx_hello.jsonl
```

`-ch` (client-hello) and `-sh` (server-hello) embed the full TLS hello messages in the JSON output. Requires ztls mode. Useful for manual fingerprint analysis, comparing against known fingerprint databases, and understanding exactly what the scan client is advertising.

### Phase 6 — Certificate chain analysis

Full chain extraction:
```
tlsx -l hosts.txt -tc -cert -vc -silent -j -o tlsx_chains.jsonl
```

`-tc` (tls-chain) includes every certificate in the chain (leaf → intermediate → root) in the JSON output. `-cert` includes the leaf certificate as PEM. `-vc` validates the chain. The combination enables:
- Intermediate CA inventory (which CAs issued certs for the target)
- Cross-signed chain detection
- Missing intermediate identification (chain incomplete → browsers may fail)
- Root CA pinning verification

Serial number extraction for CRL cross-reference:
```
tlsx -l hosts.txt -se -hash sha256 -silent -j -o tlsx_serial.jsonl
```

`-se` outputs the certificate serial number. Combined with `-hash sha256`, this gives the unique identity needed to look up a specific certificate in CRL databases or CT logs.

### Engagement workflow — full TLS recon pipeline

```
# 1. Discover all cert-visible hostnames
tlsx -l scope_hosts.txt -p 443,8443,465,993 -san -cn -dns -silent -o tlsx_discovered.txt

# 2. Resolve discovered hostnames
cat tlsx_discovered.txt | dnsx -silent -a -resp -j -o dns_resolved.jsonl

# 3. Live-check resolved hosts
cat tlsx_discovered.txt | dnsx -silent | httpx -silent -title -status-code -j -o httpx_live.jsonl

# 4. Misconfiguration sweep on live hosts
tlsx -l scope_hosts.txt -ex -ss -mm -un -vc -silent -j -o tlsx_misconfig.jsonl

# 5. Crypto audit on high-value targets
tlsx -l high_value.txt -ve -ce -ct weak,insecure -silent -j -o tlsx_crypto.jsonl

# 6. JARM fingerprint for clustering
tlsx -l scope_hosts.txt -jarm -so -silent -j -o tlsx_jarm.jsonl
```

---

## Detection

### Connection pattern signature

tlsx in default mode (`-sm auto`) opens and completes TLS handshakes rapidly across many targets. The distinctive pattern is:
- High rate of TCP SYN → TLS ClientHello → ServerHello → immediate close (no HTTP request follows)
- No application-layer data after the handshake completes
- Connections from a single source IP to many destination IPs on port 443

Network monitoring (IDS/flow analysis) sees connection-only behavior — TLS sessions that never carry application data are unusual for legitimate clients.

### Cipher enumeration fingerprint

`-ce` (cipher-enum) produces a distinctive pattern: many rapid TLS connections to the same host, each offering a different single cipher suite. The per-target connection count equals the number of cipher suites tested (potentially 100+). This is highly distinctive — normal clients send a single ClientHello with a cipher list, not many with one cipher each.

`-cec` (cipher-concurrency) controls how many of these parallel cipher probes hit the same target simultaneously. High `-cec` makes the enumeration faster but more visible.

### Scan mode TLS fingerprints

Different `-sm` modes produce different ClientHello fingerprints:
- **ctls** (crypto/tls — Go's standard library): produces a Go-standard ClientHello with Go's default cipher suite order and extensions. Matches the JA3 of any Go HTTP client. Relatively common.
- **ztls** (zcrypto/tls): produces a distinctive ClientHello different from standard Go TLS. Less common in normal traffic. Required for `-ja3`, `-ja3s`, `-ch`, `-sh`, `-ps`.
- **openssl**: uses the system OpenSSL binary (path configurable via `-ob`). Produces OpenSSL's default ClientHello — the most common TLS fingerprint on the internet. Least distinctive.
- **auto**: selects ctls by default, ztls when a ztls-only probe is requested.

Fingerprint-aware monitors can match the scanning client's JA3 against known scanner signatures. The JA3 of `ctls` matches generic Go clients; `openssl` matches generic OpenSSL; `ztls` is more distinctive.

### Pre-handshake pattern

`-ps` (pre-handshake) connects and sends a ClientHello but terminates before completing the handshake. On the wire, this appears as:
- TCP SYN → SYN-ACK → ACK → ClientHello → immediate RST/FIN
- No ServerHello response is processed

This is faster than a full handshake but produces a visible pattern: many incomplete TLS sessions from the same source. Some WAFs and TLS-aware IDS flag early-termination patterns.

### CT log access

CT log streaming (`-ctl`) makes no connection to target infrastructure. Connections go to CT log servers (operated by Google, Cloudflare, etc.). The target cannot detect or block CT-based reconnaissance. The only visibility is at the CT log operator level, which does not expose queries to certificate subjects.

### Rate-based detection

Default concurrency is 300 threads with no delay. Against a single host (cipher enum, version enum), this produces hundreds of connections in seconds. Rate-limiters, fail2ban-style tools, and cloud WAFs (Cloudflare, AWS WAF) may trigger on connection-rate alone, even though no HTTP request is sent — the TLS handshake itself is sufficient for rate counting on many platforms.

---

## Bypass and Evasion

### Scan mode selection for fingerprint control

Choose `-sm` to match desired fingerprint profile:
- **Blend with normal traffic**: `-sm openssl` — OpenSSL's ClientHello is the most common on the internet. Less likely to trigger JA3-based detection.
- **Blend with Go services**: `-sm ctls` — matches Go HTTP clients, common in cloud-native environments.
- **Need JA3/pre-handshake**: `-sm ztls` is required. Accept the more distinctive fingerprint.

```
tlsx -l hosts.txt -san -sm openssl -silent -j -o tlsx_stealth.jsonl
```

### Cipher input for ClientHello control

`-ci` overrides the cipher suites offered in the ClientHello:
```
tlsx -l hosts.txt -san -ci "TLS_AES_128_GCM_SHA256,TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256" -silent -j -o tlsx.jsonl
```

Offering only a small set of modern ciphers produces a ClientHello that resembles a modern browser rather than a scanning tool. Changes the resulting JA3 hash. Effectiveness is situational — helps against JA3-matching defenses, irrelevant against rate-based detection.

### SNI manipulation

Default behavior sends the target hostname as SNI. Override with:
- `-sni <host>` — explicit SNI; use when probing an IP to specify which cert to request:
  ```
  tlsx -u 1.2.3.4 -sni target.tld -san -silent -j -o tlsx_sni.jsonl
  ```
- `-rs` (random-sni) — sends a random hostname as SNI when the target field is empty. Useful for probing IPs without revealing interest in a specific hostname. The server may return a default cert or reject the connection.
- `-rps` (rev-ptr-sni) — performs a reverse PTR lookup on the target IP and uses the result as SNI. Useful for IP-range scanning where hostnames are unknown:
  ```
  tlsx -l ips.txt -rps -san -silent -j -o tlsx_revptr.jsonl
  ```

SNI manipulation affects what certificate the server returns, not just evasion — wrong SNI on SNI-routing hosts returns a different (or no) cert.

### Rate and concurrency control

Reduce connection rate to avoid triggering rate-limiters:
```
tlsx -l hosts.txt -san -c 10 -delay 1s -timeout 10 -silent -j -o tlsx_slow.jsonl
```

`-c 10` limits to 10 concurrent connections. `-delay 1s` adds 1 second between connections per thread. Effective connection rate is approximately `c / delay` = 10/s.

For cipher enumeration specifically:
```
tlsx -l hosts.txt -ce -c 5 -cec 3 -delay 2s -silent -j -o tlsx_cipher_stealth.jsonl
```

`-cec 3` limits cipher probes per target to 3 at a time. Combined with `-c 5` and `-delay 2s`, the effective per-target probe rate is very low.

### SOCKS5 proxy routing

Route connections through a SOCKS5 proxy for source-IP control:
```
tlsx -l hosts.txt -san -proxy socks5://127.0.0.1:1080 -silent -j -o tlsx_proxy.jsonl
```

The proxy sees TLS ClientHello traffic. The target sees the proxy's IP. Useful for distributing scan origin across multiple proxy endpoints. Does not change the TLS fingerprint itself.

### TLS version constraining

`-min-version` and `-max-version` constrain the TLS versions offered in ClientHello:
```
tlsx -l hosts.txt -san -min-version tls12 -max-version tls13 -silent -j -o tlsx.jsonl
```

Offering only TLS 1.2+ produces a more modern-looking ClientHello. Offering legacy versions (tls10, ssl30) is unusual for modern clients and may flag as scanning behavior.

### Evasion effectiveness summary

| Technique | Controls | Effective against | Not effective against |
|---|---|---|---|
| `-sm openssl` | ClientHello/JA3 | JA3-based fingerprinting | Rate-based, behavioral |
| `-ci <ciphers>` | Cipher list in ClientHello | JA3-based fingerprinting | Rate-based, behavioral |
| `-delay`/`-c` | Connection rate | Rate-limiters, fail2ban | JA3-based, protocol analysis |
| `-proxy` | Source IP | IP-based blocking | TLS fingerprinting, behavioral |
| `-sni` | SNI hostname | SNI-based routing/logging | Connection pattern analysis |
| `-min-version`/`-max-version` | TLS version offer | Version-anomaly detection | Rate-based, JA3-based |

All evasion is situational. TLS connections without subsequent application data are inherently unusual. Evasion reduces one signature at a time; no combination fully blends with normal traffic.

---

## Techniques

### JARM fingerprinting deep-dive

JARM works by sending 10 TLS ClientHello packets with varying parameters (TLS versions, ciphers, extensions) and hashing the server responses. The 62-character hash encodes the server's negotiation behavior.

Collect JARM + cert metadata for correlation analysis:
```
tlsx -l all_hosts.txt -jarm -san -cn -so -tv -cipher -hash sha256 -silent -j -o tlsx_jarm_corr.jsonl
```

Post-process to find infrastructure clusters:
```
jq -r '[.jarm, .subject_org, .host] | @tsv' tlsx_jarm_corr.jsonl | sort | uniq -c | sort -rn
```

Hosts with identical JARM + same organization = shared infrastructure. Same JARM + different organization = shared hosting, CDN, or same reverse-proxy product.

Known JARM patterns (lookup, not hardcoded — check against current databases):
- Cloudflare, AWS ALB/CloudFront, Akamai, Fastly each produce distinctive JARMs
- Default Nginx, Apache, IIS configurations produce recognizable JARMs
- C2 frameworks (Cobalt Strike, Sliver, Metasploit) have documented JARM fingerprints

Compare JARM results with `wafw00f` output: if wafw00f identifies "Cloudflare" and JARM matches the known Cloudflare fingerprint, the WAF identification is corroborated. If JARM differs, the target may be behind a custom configuration or a different CDN tier.

### JA3/JA3S analysis (ztls mode)

JA3 hashes the ClientHello parameters (TLS version, ciphers, extensions, elliptic curves, point formats) into an MD5 fingerprint. JA3S does the same for the ServerHello.

Capture both plus the raw hello messages:
```
tlsx -u target.tld -ja3 -ja3s -ch -sh -sm ztls -j -o tlsx_ja3_deep.jsonl
```

The JA3 in output is tlsx's own ClientHello fingerprint — what the target sees from the scanning client. Compare against:
- Defender JA3 blocklists to check if the scan fingerprint is blocked
- Browser JA3 databases to understand how the scan fingerprint differs from normal traffic

JA3S in output is the server's response fingerprint. Identical JA3S across different hosts indicates identical server TLS configuration — another clustering signal alongside JARM.

`-ch`/`-sh` embed the full hello messages for manual inspection when the hash alone is insufficient. Parse with jq:
```
jq '.client_hello.cipher_suites' tlsx_ja3_deep.jsonl
```

### CT log streaming patterns

Incremental monitoring setup:
```
# First run — stream current CT entries
tlsx -ctl -san -cn -silent -j -o ct_run1.jsonl

# Track the last index per source from the output
jq -r '[.ctl_source_id, .ctl_index] | @tsv' ct_run1.jsonl | sort -t$'\t' -k1,1 -k2,2nr | sort -t$'\t' -k1,1 -u > ct_checkpoints.txt

# Next run — resume from checkpoints
# (format: -cti "sourceA=12345,sourceB=67890")
tlsx -ctl -cti "$(awk '{printf "%s=%s,", $1, $2}' ct_checkpoints.txt | sed 's/,$//')" -san -cn -silent -j -o ct_run2.jsonl
```

Targeted domain monitoring from CT stream:
```
tlsx -ctl -san -cn -silent | grep -iE '\.target\.tld"' | tee -a ct_target_monitor.jsonl
```

This runs indefinitely, appending only entries mentioning the target domain. Combine with `timeout` or run as a background process with periodic output review.

Bounded historical replay:
```
timeout 300 tlsx -ctl -cb -san -cn -silent -j -o ct_historical.jsonl
```

`-cb` starts from index 0 — the beginning of each log. This produces massive output. Always bound with `timeout`. Useful for building a comprehensive historical subdomain inventory before an engagement.

### Cipher enumeration workflow

Full audit — all cipher types:
```
tlsx -l hosts.txt -ce -ve -silent -j -o tlsx_cipher_full.jsonl
```

Focused — weak and insecure only (compliance scope):
```
tlsx -l hosts.txt -ce -ct weak,insecure -silent -j -o tlsx_cipher_weak.jsonl
```

Secure-only check (verify no unexpected cipher downgrades):
```
tlsx -l hosts.txt -ce -ct secure -silent -j -o tlsx_cipher_secure.jsonl
```

Per-target cipher concurrency tuning:
```
tlsx -u target.tld -ce -cec 20 -silent -j -o tlsx_cipher_fast.jsonl
```

Higher `-cec` runs more cipher probes in parallel against the same target, finishing faster but creating more simultaneous connections.

Test with a specific cipher input to verify server acceptance:
```
tlsx -u target.tld -ci "TLS_RSA_WITH_RC4_128_SHA" -cipher -tv -silent -j
```

If the server negotiates the offered cipher, it accepts that weak cipher. If it rejects (connection fails), the server correctly refuses it.

### Pre-handshake mode for fast scanning

`-ps` (pre-handshake) uses ztls to perform an early-termination handshake — sends ClientHello, optionally receives partial ServerHello, and disconnects before the handshake completes:
```
tlsx -l large_scope.txt -ps -tps -silent -j -o tlsx_prehands.jsonl
```

Faster than a full handshake because it skips certificate exchange, key agreement, and Finished messages. Trade-off: probes that require the certificate (SAN, CN, serial, hash, chain) cannot work with `-ps` — only `-tps` (probe status: did the TLS port respond?) is meaningful.

Use `-ps` for rapid "is TLS alive on this port" sweeps across large IP ranges, then follow up with a full probe on responsive hosts:
```
# Fast alive check
tlsx -l all_ips.txt -p 443,8443 -ps -tps -silent -o tlsx_alive.txt
# Full probe on alive hosts
tlsx -l tlsx_alive.txt -san -cn -jarm -tv -cipher -silent -j -o tlsx_full.jsonl
```

### Scan-all-IPs for CDN/geo-DNS cert variance

`-sa` resolves every A/AAAA record for each hostname and probes each IP independently:
```
tlsx -l cdn_hosts.txt -sa -san -cn -jarm -silent -j -o tlsx_allip.jsonl
```

CDN-fronted hosts may present different certificates per edge node. Origin servers behind a CDN sometimes leak their real certificate (with origin SANs) on specific edge IPs. Compare SAN sets per IP to detect origin cert leakage.

Combine with `-iv 4` or `-iv 6` to test specific address families:
```
tlsx -l hosts.txt -sa -iv 6 -san -silent -j -o tlsx_ipv6.jsonl
```

IPv6 endpoints sometimes serve different certs or have different TLS configurations than their IPv4 counterparts.

### SNI-based virtual host discovery

When scanning an IP that hosts multiple domains (shared hosting, cloud platforms), iterate SNI values to extract each domain's certificate:
```
tlsx -u 1.2.3.4 -sni target1.tld,target2.tld,target3.tld -san -cn -silent -j -o tlsx_vhost.jsonl
```

For bulk SNI probing from a candidate list:
```
cat candidate_domains.txt | while read domain; do
  tlsx -u 1.2.3.4 -sni "$domain" -san -cn -tps -silent -j
done > tlsx_sni_enum.jsonl
```

Hosts returning different certificates per SNI value confirm virtual hosting. Hosts returning the same default cert regardless of SNI indicate SNI is not used for routing, or the SNI value is unrecognized.

Reverse-PTR SNI (`-rps`) automates this for IP ranges:
```
tlsx -l ip_range.txt -rps -san -cn -silent -j -o tlsx_rps.jsonl
```

Each IP's reverse DNS record becomes the SNI, requesting the certificate the server associates with that PTR name.

### Revocation checking workflow

Standard revocation check:
```
tlsx -l important_hosts.txt -re -vc -silent -j -o tlsx_revoked.jsonl
```

`-re` queries OCSP responders and downloads CRLs for each certificate. This is network-intensive — each cert may trigger a CRL download of several MB.

Strict revocation with hardfail:
```
tlsx -l important_hosts.txt -re -hf -vc -silent -j -o tlsx_revoked_strict.jsonl
```

`-hf` treats OCSP/CRL retrieval failures as revoked. Without `-hf`, a network error during revocation check is reported as "unknown" rather than "revoked". Use `-hf` for strict compliance checking where revocation infrastructure availability is itself a requirement.

Scope `-re` tightly — run only on high-value hosts where revocation status matters (production domains, financial services, compliance targets). On broad scope, the CRL/OCSP traffic dominates runtime and bandwidth.

### Certificate fingerprint matching

Hash-based cert identification across hosts:
```
tlsx -l hosts.txt -hash sha256 -san -cn -silent -j -o tlsx_hashes.jsonl
```

Find hosts sharing the same certificate:
```
jq -r '[.certificate_hash, .host] | @tsv' tlsx_hashes.jsonl | sort | awk -F'\t' '{a[$1] = a[$1] " " $2} END {for (h in a) if (split(a[h], b, " ") > 2) print h, a[h]}'
```

Hosts sharing a certificate hash are either behind the same load balancer, using the same wildcard cert, or have the same cert deployed independently.

### Output parsing and automation

Extract SANs as a flat list:
```
jq -r '.subject_an[]?' tlsx_san.jsonl | sort -u
```

Filter for specific TLS versions:
```
jq -r 'select(.tls_version == "tls10") | .host' tlsx_full.jsonl
```

Extract JARM clusters:
```
jq -r '[.jarm, .host] | @tsv' tlsx_jarm.jsonl | sort | awk -F'\t' '{a[$1]++; b[$1] = b[$1] " " $2} END {for (j in a) if (a[j] > 1) print j, a[j], b[j]}'
```

Extract misconfigurations by type:
```
jq -r 'select(.expired == true) | .host' tlsx_misconfig.jsonl > expired_hosts.txt
jq -r 'select(.self_signed == true) | .host' tlsx_misconfig.jsonl > selfsigned_hosts.txt
jq -r 'select(.mismatched == true) | .host' tlsx_misconfig.jsonl > mismatched_hosts.txt
```

---

## Tool-to-tool chaining

### tlsx → dnsx → httpx (cert-driven asset pipeline)

The canonical recon chain: discover hostnames via certs, resolve them, live-check them:
```
tlsx -l scope.txt -p 443,8443 -dns -silent | sort -u | dnsx -silent | httpx -silent -title -status-code -tech-detect -j -o pipeline_live.jsonl
```

### subfinder → tlsx (validate passive subdomains via cert)

Subfinder discovers subdomains passively; tlsx confirms which ones serve TLS and extracts their cert data:
```
subfinder -d target.tld -all -silent | tlsx -san -cn -tv -jarm -silent -j -o tlsx_subfinder.jsonl
```

Hosts that return a valid cert with matching SAN are confirmed live TLS endpoints. Hosts that fail to connect or return mismatched certs may be stale, pointed at CDN catchalls, or candidates for subdomain takeover investigation.

### naabu → tlsx (port scan → TLS probe)

After naabu discovers open ports, probe TLS on each:
```
naabu -l hosts.txt -p 443,8443,9443,465,993 -silent | tlsx -san -cn -tv -silent -j -o tlsx_naabu.jsonl
```

This catches TLS services on non-standard ports that a 443-only tlsx scan would miss.

### tlsx JARM → wafw00f correlation

Compare tlsx JARM fingerprints with wafw00f WAF identification:
```
tlsx -l hosts.txt -jarm -silent -j -o tlsx_jarm.jsonl
wafw00f -i hosts.txt -a -f json -o wafw00f.json
```

Cross-reference: if wafw00f identifies "Cloudflare" and the JARM matches known Cloudflare JARMs, the identification is confirmed. Divergence suggests custom configuration, a different CDN tier, or a WAF behind another reverse proxy.

### tlsx → nuclei (cert-based vulnerability scanning)

Feed misconfiguration findings to nuclei for deeper validation:
```
jq -r 'select(.expired == true or .self_signed == true or .mismatched == true) | .host' tlsx_misconfig.jsonl | nuclei -t ssl/ -silent -j -o nuclei_ssl.jsonl
```

Nuclei's `ssl/` template folder contains checks that build on the same signals tlsx detects — expired certs, weak ciphers, known vulnerable implementations.

### tlsx cert SANs → katana/gospider (crawl cert-discovered hosts)

Newly discovered hostnames from SAN harvesting feed the crawler for endpoint discovery:
```
tlsx -l scope.txt -dns -silent | httpx -silent | katana -silent -jc -d 3 -o katana_cert_hosts.txt
```

---

## Failure recovery

- Empty SANs on known-cert hosts: verify the host actually serves TLS on the port (`-p 443` default; try `-p 8443`), raise `-timeout`, drop `-sm ztls` and let `auto` pick.
- `-re` runs forever: that's expected — CRL downloads are large. Drop `-re` unless revocation is the specific question. Scope to a short target list.
- Many timeouts: lower `-c`, raise `-timeout`, add `-delay 100ms`.
- CT stream fills the disk: cap wall-clock with `timeout <N>s tlsx -ctl ...` or filter with a downstream `jq` + wordcount.
- Cipher enum returns no insecure ciphers but compliance requires documentation: re-run with `-ce -ct all` and document the full accepted cipher list (the absence of weak ciphers is itself a finding).
- JARM returns all zeros (`00000000000000000000000000000000000000000000000000000000000000`): the server did not respond to enough JARM probes. Often caused by aggressive rate-limiting or a non-TLS service on the port. Not a valid fingerprint — exclude from clustering.
- `-ja3`/`-ja3s` empty: verify `-sm ztls` is set — these probes require ztls mode and silently produce no output under ctls/auto/openssl.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io tlsx <flag> usage`

## Routed consumers

- `reconnaissance/*` (cert SAN inventory → asset discovery)
- `vulnerabilities/subdomain_takeover.md` (cert SAN + CNAME + dangling-record is the primitive)
- `vulnerabilities/weak_password_storage.md` (weak TLS crypto audit overlaps with transport-layer findings)
- `tooling/dnsx.md` (resolve the SANs you harvested)
- `tooling/httpx.md` (live-check cert-discovered hosts)
- `tooling/subfinder.md` (complementary — subfinder uses many passive sources including CT; tlsx streams CT directly and extracts live certs)
- `tooling/naabu.md` (port discovery → TLS probe on discovered ports)
- `tooling/wafw00f.md` (JARM correlation with WAF identification)
- `tooling/nuclei.md` (cert-based vulnerability templates in `ssl/`)
- `tooling/katana.md` (crawl cert-discovered hosts)
