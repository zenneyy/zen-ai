---
name: naabu
description: Naabu port-scanning syntax with host input, scan-type, verification, and rate controls.
---

# Naabu CLI Playbook

Official docs:
- https://docs.projectdiscovery.io/opensource/naabu/usage
- https://docs.projectdiscovery.io/opensource/naabu/running
- https://github.com/projectdiscovery/naabu

Canonical syntax:
`naabu [flags]`

## Complete Flag Reference (naabu v2.6.1, verified in zen-sandbox 1.2.2)

INPUT:
- `-host <host>` hosts to scan (comma-separated)
- `-list, -l <file>` hosts list from file
- `-exclude-hosts, -eh <hosts>` hosts to exclude (comma-separated)
- `-exclude-file, -ef <file>` hosts to exclude from file

PORT:
- `-port, -p <ports>` ports to scan (e.g. `80,443`, `100-200`)
- `-top-ports, -tp <n|full>` top ports profile: `100` (default), `1000`, `full`
- `-exclude-ports, -ep <ports>` ports to exclude (file or comma-separated)
- `-ports-file, -pf <file>` ports list from file (one per line or comma-separated)
- `-port-threshold, -pts <n>` skip port scan for hosts with more than `n` open ports (noisy responders / honeypots)
- `-exclude-cdn, -ec` skip full port scan for CDN/WAF hosts — scan only 80,443
- `-display-cdn, -cdn` display detected CDN provider in output

RATE-LIMIT:
- `-c <n>` internal worker threads (default 25)
- `-rate <n>` packets per second (default 1000)

OUTPUT:
- `-o, -output <file>` output file
- `-j, -json` JSONL output
- `-csv` CSV output
- `-lof, -list-output-fields` list available output fields
- `-eof, -exclude-output-fields <fields>` exclude specific fields from output

CONFIGURATION:
- `-config <file>` config file path (default `$HOME/.config/naabu/config.yaml`)
- `-scan-all-ips, -sa` scan all IPs associated with a hostname's DNS record
- `-ip-version, -iv <4|6>` IP version to scan (default both `4,6`)
- `-scan-type, -s <SYN|CONNECT>` scan type (default `c` = CONNECT)
- `-source-ip <x.x.x.x:port>` source IP and optional port for outbound packets
- `-connect-payload, -cp <string>` payload to send in CONNECT scans
- `-interface-list, -il` list available network interfaces and public IP
- `-interface, -i <iface>` network interface to bind to
- `-nmap-cli <cmd>` nmap command to run on discovered ports (e.g. `-nmap-cli 'nmap -sV'`)
- `-r <resolvers>` custom DNS resolvers (comma-separated or file)
- `-proxy <socks5://host:port>` SOCKS5 proxy
- `-proxy-auth <user:pass>` SOCKS5 proxy authentication
- `-dns-order <p|l|lp|pl>` DNS resolution order: `p` (probe), `l` (local), `lp`, `pl` (default `l`)
- `-sr, -system-resolver` use system DNS as fallback resolver
- `-resume` resume scan using `resume.cfg`
- `-stream` stream mode — disables resume, verify, retries, shuffling for raw speed
- `-passive` passive port enumeration via Shodan InternetDB (no packets sent)
- `-irt, -input-read-timeout <duration>` timeout on input read (default `3m0s`)
- `-no-stdin` disable stdin processing

HOST-DISCOVERY:
- `-sn, -host-discovery` perform host discovery only (no port scan)
- `-Pn, -skip-host-discovery` skip host discovery — assume all hosts are up
- `-wn, -with-host-discovery` enable host discovery before port scan
- `-ps, -probe-tcp-syn <ports>` TCP SYN ping on specified ports
- `-pa, -probe-tcp-ack <ports>` TCP ACK ping on specified ports
- `-pe, -probe-icmp-echo` ICMP echo request ping
- `-pp, -probe-icmp-timestamp` ICMP timestamp request ping
- `-pm, -probe-icmp-address-mask` ICMP address mask request ping
- `-arp, -arp-ping` ARP ping (LAN only)
- `-nd, -nd-ping` IPv6 Neighbor Discovery ping
- `-rev-ptr` reverse PTR lookup for input IPs

SERVICES-DISCOVERY:
- `-sD, -service-discovery` identify services on discovered ports
- `-sV, -service-version` detect service versions (uses nmap-service-probes)

OPTIMIZATION:
- `-retries <n>` retry count per port (default 3)
- `-timeout <duration>` per-probe timeout (default `1s` — millisecond-granularity internally)
- `-warm-up-time <sec>` delay in seconds between scan phases (default 2)
- `-ping` send ping probes for host verification
- `-verify` validate open ports with TCP verification after scan
- `-ss, -smart-scan` predictive port scanning using port correlation model
- `-pt, -prediction-threshold <0-100>` minimum confidence for predicted ports (default 20)

DEBUG:
- `-health-check, -hc` run diagnostic check
- `-debug` display debug information
- `-verbose, -v` verbose output
- `-no-color, -nc` disable colors
- `-silent` show only results
- `-version` display version
- `-mp, -metrics-port <port>` expose Prometheus metrics (default 63636)

## Agent-Safe Baseline

`naabu -list hosts.txt -top-ports 100 -scan-type c -Pn -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -j -o naabu.jsonl`

## Common Patterns

Top ports with controlled rate:
`naabu -list hosts.txt -top-ports 100 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent -o naabu.txt`

Focused web-ports sweep:
`naabu -list hosts.txt -p 80,443,8080,8443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify -silent`

Single-host quick check:
`naabu -host target.tld -p 22,80,443 -scan-type c -rate 300 -c 25 -timeout 1000 -retries 1 -verify`

Full port scan (all 65535):
`naabu -host target.tld -p - -scan-type c -rate 500 -c 50 -timeout 800 -retries 1 -verify -silent -j -o naabu_full.jsonl`

SYN scan (requires root/raw socket):
`sudo naabu -list hosts.txt -top-ports 1000 -scan-type s -rate 1000 -c 50 -timeout 800 -retries 1 -verify -silent -j -o naabu_syn.jsonl`

Host discovery only (no port scan):
`naabu -list hosts.txt -sn -pe -ps 80,443 -pa 443 -silent -o alive.txt`

Host discovery with ARP on a LAN:
`naabu -list lan_hosts.txt -sn -arp -silent -o alive_lan.txt`

Service discovery on found ports:
`naabu -host target.tld -top-ports 100 -scan-type c -sD -silent -j -o naabu_svc.jsonl`

Service version detection:
`naabu -host target.tld -p 22,80,443,3306,5432,8080 -scan-type c -sV -silent -j -o naabu_ver.jsonl`

Smart scan (predictive):
`naabu -host target.tld -top-ports 100 -scan-type c -ss -pt 30 -verify -silent -j -o naabu_smart.jsonl`

Passive mode (Shodan InternetDB, no packets):
`naabu -host target.tld -passive -silent -j -o naabu_passive.jsonl`

CDN-aware scan (detect CDN, skip full scan on CDN hosts):
`naabu -list hosts.txt -top-ports 100 -scan-type c -ec -cdn -rate 300 -verify -silent -j -o naabu_cdn.jsonl`

Scan all DNS-resolved IPs:
`naabu -host target.tld -top-ports 100 -sa -scan-type c -rate 300 -verify -silent -j -o naabu_allips.jsonl`

nmap follow-up on discovered ports:
`naabu -host target.tld -top-ports 100 -scan-type c -verify -silent -nmap-cli 'nmap -sV -sC -oA nmap_out'`

Stream mode (maximum speed, no verification):
`naabu -list hosts.txt -top-ports 100 -scan-type c -stream -rate 2000 -c 100 -silent -o naabu_stream.txt`

Resume an interrupted scan:
`naabu -resume`

Reverse PTR lookup for IP list:
`naabu -list ips.txt -sn -rev-ptr -silent`

Proxied CONNECT scan:
`naabu -host target.tld -top-ports 100 -scan-type c -proxy socks5://127.0.0.1:1080 -proxy-auth user:pass -rate 100 -verify -silent -j -o naabu_proxy.jsonl`

CSV output with field exclusion:
`naabu -host target.tld -top-ports 100 -scan-type c -csv -eof cdn -o naabu.csv`

IPv6-only scan:
`naabu -host target.tld -iv 6 -p 80,443 -scan-type c -verify -silent`

## Critical Correctness Rules

- Default scan type is CONNECT (`-s c`). SYN (`-s s`) requires root or `CAP_NET_RAW` — it will silently fall back to CONNECT without privileges.
- `-timeout` accepts duration strings (`1s`, `500ms`). The internal unit is milliseconds. Always set explicitly; the default `1s` is sane for LAN but may need raising for remote targets.
- `-rate` is packets per second for SYN, connections per second for CONNECT. SYN at `-rate 1000` sends 1000 raw packets/s; CONNECT at `-rate 1000` opens 1000 TCP handshakes/s — the latter is heavier on both sides.
- `-verify` adds a second-pass TCP connect to every discovered port. Essential before handing results to downstream scanners; SYN scans without verification produce false positives from stateful firewalls that RST after SYN-ACK.
- `-top-ports 100` covers the 100 most commonly open ports. `-top-ports 1000` is substantially broader. `-top-ports full` scans all 65535 — equivalent to `-p -` but uses naabu's port-frequency ordering.
- `-exclude-cdn -ec` skips full port scans for hosts behind CDN/WAF — scans only 80,443. The rationale: open ports on a CDN edge are the CDN's infrastructure, not the origin server's. Without `-ec`, CDN hosts inflate the result set with CDN-owned ports.
- `-port-threshold -pts` skips hosts responding on too many ports (threshold exceeded = likely honeypot or SYN-ACK-all responder). Useful on large-scale scans where a few hosts would drown the output.
- `-passive` queries Shodan InternetDB — no packets leave the scanner. Coverage depends on Shodan's last scan of the target; stale data is possible. Use as a fast pre-check, not a replacement for active scanning.
- `-stream` sacrifices resume, verification, retries, and host shuffling for raw throughput. Results from stream mode should be treated as preliminary — follow with `-verify` on interesting hosts.
- `-nmap-cli` expects a quoted nmap command string. naabu passes discovered `host:port` pairs to it. nmap must be installed on the system (it is in the sandbox).
- Host discovery runs automatically before CONNECT/SYN scans when the process has sufficient privileges. `-Pn` skips it (scan all hosts regardless); `-sn` runs discovery only. Explicit probe flags (`-ps`, `-pa`, `-pe`, etc.) select which probe methods are used.

## Usage Rules

- Keep host discovery behavior explicit: `-Pn` for scan-everything, `-sn` for discovery-only, default for automatic discovery-then-scan.
- Use `-j -o <file>` or `-csv -o <file>` for automation pipelines.
- Prefer `-p 22,80,443,8080,8443` or `-top-ports 100` over larger sweeps unless broader coverage is explicitly required.
- Pin `-rate` and `-c` explicitly for reproducible, non-disruptive scans.
- Combine `-sV` with `-verify` — version detection on false-positive ports wastes time.
- Use `-ec -cdn` together on mixed-infrastructure targets to both detect and handle CDN hosts.
- Do not use `-h`/`--help` for normal flow unless absolutely necessary.

## Failure Recovery

- Privileged socket errors on SYN scan: switch to `-scan-type c`.
- Scans slow or lossy: lower `-rate`, lower `-c`, tighten `-p`/`-top-ports`.
- Many hosts appear down: compare runs with and without `-Pn`; try alternate discovery probes (`-pe`, `-ps 80,443`, `-arp` on LAN).
- Interrupted scan: `naabu -resume` reads `resume.cfg` from the working directory.
- `-sV` hangs on some ports: raise `-timeout` for the version detection phase; nmap-service-probes can be slow on non-standard services.
- CDN hosts inflating results: add `-ec` to restrict CDN hosts to 80/443.

If uncertain, query web_search with:
`site:docs.projectdiscovery.io naabu <flag> usage`

---

## Scan Types — SYN vs CONNECT

naabu supports two active scan modes, selectable with `-scan-type` (`-s`):

### SYN scan (`-s s` or `-s SYN`)

Sends raw TCP SYN packets without completing the handshake. The kernel never opens a full connection — naabu crafts packets directly via raw sockets.

**Requirements:** Root privileges or `CAP_NET_RAW`. Without them naabu silently falls back to CONNECT.

**Mechanics:**
1. Send SYN to target port.
2. SYN-ACK → port is open (naabu sends RST to tear down).
3. RST/no response → port is closed/filtered.

**Advantages:**
- Faster — no three-way handshake overhead.
- Does not create entries in application-level logs (no connection established).
- Lower per-port resource consumption on both sides.

**Disadvantages:**
- Requires privileges.
- Stateful firewalls can detect half-open scanning patterns.
- Some IDS/IPS specifically signature SYN-without-completion patterns.
- Cannot send connect payloads (`-cp`).
- Cannot use SOCKS5 proxy (`-proxy`).

### CONNECT scan (`-s c` or `-s CONNECT`)

Performs full TCP three-way handshakes using the OS network stack.

**Requirements:** None — works unprivileged. Default mode.

**Mechanics:**
1. Full SYN → SYN-ACK → ACK handshake.
2. Connection established → port is open.
3. Connection immediately closed (or payload sent if `-cp` is set).

**Advantages:**
- Works without root.
- Traverses SOCKS5 proxies (`-proxy`).
- Can send connect payloads (`-cp`) for banner-grab or protocol-trigger.
- Looks like normal TCP traffic to network devices.

**Disadvantages:**
- Slower — full handshake per port per retry.
- Creates entries in application connection logs.
- Heavier on both scanner and target (full socket allocation).

### Mode selection guidance

| Scenario | Mode | Rationale |
|---|---|---|
| Sandbox default (non-root) | CONNECT | Privilege constraint |
| Root available, speed critical | SYN | Raw throughput, no log entries |
| Target behind proxy/VPN | CONNECT | SYN can't traverse SOCKS5 |
| Stealth vs application logs | SYN | No application-level connection record |
| Need connect payload (`-cp`) | CONNECT | SYN doesn't complete handshake |
| Accurate results, any mode | Either + `-verify` | Verification is orthogonal to scan type |

---

## Host Discovery

naabu performs host discovery automatically before port scanning when running with sufficient privileges. Three control flags select the behavior:

- `-sn, -host-discovery` — discovery only, no port scan. Output is a list of live hosts.
- `-Pn, -skip-host-discovery` — skip discovery entirely, assume all hosts are up. Scan every input host.
- `-wn, -with-host-discovery` — explicitly enable discovery before the port scan (overrides any default that might skip it).

When no explicit probe is selected, naabu uses its own internal multi-method discovery. To select specific probes, pass one or more:

### TCP SYN ping (`-ps <ports>`)

Sends TCP SYN packets to the specified ports. A SYN-ACK or RST response means the host is alive. Effective against hosts that block ICMP but allow TCP to web ports.

`naabu -list hosts.txt -sn -ps 80,443 -silent -o alive.txt`

Requires raw socket (root/CAP_NET_RAW). Bypasses stateless firewalls that only filter ICMP.

### TCP ACK ping (`-pa <ports>`)

Sends TCP ACK packets. An RST response (expected — no connection exists) means the host is alive. Designed to bypass stateful firewalls that filter SYN packets but pass ACK.

`naabu -list hosts.txt -sn -pa 443 -silent -o alive.txt`

Requires raw socket. Effective against firewalls that block unsolicited SYN but permit ACK (expecting it belongs to an established connection).

### ICMP echo ping (`-pe`)

Standard ICMP echo request (ping). The simplest and fastest probe; widely filtered on the public internet but reliable on internal networks.

`naabu -list hosts.txt -sn -pe -silent -o alive.txt`

### ICMP timestamp ping (`-pp`)

ICMP timestamp request (type 13). Some hosts respond to timestamp requests while filtering echo requests — a fallback for ICMP-filtered environments.

`naabu -list hosts.txt -sn -pp -silent -o alive.txt`

### ICMP address mask ping (`-pm`)

ICMP address mask request (type 17). Rarely responded to on modern systems but occasionally works on legacy network devices and embedded systems.

### ARP ping (`-arp`)

ARP resolution on the local network segment. If the host answers the ARP request, it is alive. The fastest and most reliable discovery method on a LAN — ARP cannot be firewall-filtered at layer 2.

`naabu -list 192.168.1.0/24 -sn -arp -silent -o alive_lan.txt`

LAN only. Does not traverse routers.

### IPv6 Neighbor Discovery (`-nd`)

IPv6 Neighbor Solicitation (the IPv6 equivalent of ARP). Discovers live IPv6 hosts on the local link.

`naabu -list fe80::/64 -sn -nd -iv 6 -silent -o alive_v6.txt`

### Reverse PTR lookup (`-rev-ptr`)

Performs reverse DNS lookups on input IPs. Not a liveness probe — it queries DNS for PTR records. Useful for hostname enumeration from IP ranges.

`naabu -list ips.txt -sn -rev-ptr -silent`

### Probe selection strategy

Combine probes for maximum coverage against filtered environments:

`naabu -list hosts.txt -sn -pe -ps 80,443 -pa 443 -silent -o alive.txt`

Selection by target environment:

| Environment | Probes | Rationale |
|---|---|---|
| Internal LAN | `-arp` (or `-nd` for IPv6) | Layer 2, unfilterable |
| DMZ / perimeter | `-ps 80,443 -pa 443` | TCP probes bypass ICMP filters |
| Cloud / VPS | `-pe -ps 80,443` | ICMP often allowed; TCP as fallback |
| Heavily filtered | `-ps 80,443 -pa 80,443 -pe -pp` | Stack multiple probe types |
| IPv6 link-local | `-nd -iv 6` | ND is the IPv6 equivalent of ARP |

---

## Service Discovery and Version Detection

### Service discovery (`-sD`)

Identifies the service running on each discovered port by port number and protocol signature. Lightweight — uses a service-to-port mapping table, not deep probing.

`naabu -host target.tld -top-ports 100 -sD -verify -silent -j -o naabu_svc.jsonl`

JSONL output includes a `service` field with the identified service name (e.g. `http`, `ssh`, `mysql`).

### Service version detection (`-sV`)

Performs active service fingerprinting using nmap-service-probes. Sends protocol-specific probe packets to each open port and matches responses against the nmap service signature database.

`naabu -host target.tld -p 22,80,443,3306,5432,8080 -sV -verify -silent -j -o naabu_ver.jsonl`

JSONL output includes `service` and `version` fields.

**Differences:**

| Feature | `-sD` | `-sV` |
|---|---|---|
| Method | Port-number lookup table | Active probe + signature match |
| Accuracy | Assumes standard port assignments | Identifies actual running service |
| Speed | Instant (no extra traffic) | Adds per-port probe + response time |
| Non-standard ports | Misidentifies | Correctly identifies |
| Use case | Quick overview / pipeline enrichment | Accurate service inventory |

**Guidelines:**
- Use `-sD` for fast enrichment when port assignments are standard.
- Use `-sV` when accuracy matters — non-standard ports, unknown services, or feeding results to vulnerability scanners that need exact versions.
- Always combine with `-verify` — version-probing false-positive ports wastes time and pollutes results.
- `-sV` increases scan duration per port. For large scans, run a fast port-only pass first, then `-sV` on confirmed interesting hosts.

---

## Smart Scan — Predictive Port Scanning

`-ss, -smart-scan` enables predictive port scanning using a port correlation model. When naabu discovers certain ports open, the model predicts additional ports likely to be open on the same host.

`naabu -host target.tld -top-ports 100 -ss -pt 30 -verify -silent -j -o naabu_smart.jsonl`

### How it works

The correlation model encodes statistical relationships between port openness. Common correlations:
- Port 80 open → likely 443 also open.
- Port 22 open → likely a server, check common server ports (3306, 5432, 8080, 6379, etc.).
- Port 25 open → likely a mail server, check 143, 993, 587, 110, 995.

When the initial scan discovers ports, the model generates predictions above the confidence threshold (`-pt`, default 20%). Those predicted ports are added to the scan queue.

### Confidence threshold (`-pt`)

- `-pt 20` (default): aggressive prediction — many additional ports scanned, some will be false predictions.
- `-pt 50`: moderate — scan only ports with ≥50% confidence.
- `-pt 80`: conservative — scan only high-confidence predictions.

### When to use smart scan

- **Large target lists with limited time:** smart scan finds more ports with fewer probes than a flat top-1000 sweep.
- **Reconnaissance where coverage matters but full-port scan is impractical:** the model surfaces likely-open ports without scanning all 65535.
- **Not a replacement for full port scan:** when completeness is required, `-p -` is definitive. Smart scan is an efficiency tool, not a coverage guarantee.

### Bandwidth savings

On a typical server with ~10 open ports, smart scan may probe 200-300 ports instead of 1000+, finding 90%+ of what `-top-ports 1000` would find. The savings scale with target count.

---

## Passive Mode — Shodan InternetDB

`-passive` queries the Shodan InternetDB API for known open ports. No packets are sent to the target — the data comes from Shodan's most recent scan of that IP.

`naabu -host target.tld -passive -silent -j -o naabu_passive.jsonl`

### What it returns

InternetDB provides: open ports, detected services, hostnames, and known CVEs for a given IP. naabu extracts the port list.

### Limitations

- Data staleness: InternetDB reflects Shodan's last scan, which may be days to weeks old. Ports opened or closed since then are missed.
- Coverage: not every IP is in InternetDB; less commonly scanned ranges may have no data.
- IPv4 only: InternetDB is indexed by IPv4 address.
- No verification: results are historical, not live-confirmed. Follow with an active scan on interesting targets.

### When to use

- Pre-scan reconnaissance before active scanning — know what Shodan already found.
- Environments where active scanning is not yet authorized — passive provides prior art without touching the target.
- Quick triage of large IP ranges — identify hosts with interesting port profiles before committing to active scans.

### Passive + active workflow

`naabu -host target.tld -passive -silent -o passive.txt && naabu -host target.tld -pf passive.txt -scan-type c -verify -sV -silent -j -o naabu_verified.jsonl`

Use passive results to seed the active scan's port list — verify and version-detect only ports Shodan already identified.

---

## CDN Detection and Exclusion

### Why CDN handling matters

When a hostname resolves to a CDN edge (Cloudflare, Akamai, Fastly, AWS CloudFront), the open ports belong to the CDN infrastructure, not the origin server. A full port scan of a CDN edge returns CDN-owned ports (HTTP/HTTPS, edge services) that tell you nothing about the origin. Worse, it triggers CDN-side rate limiting.

### Display CDN (`-cdn, -display-cdn`)

Annotates output with the detected CDN provider. The detection uses IP range matching against known CDN CIDR blocks.

`naabu -list hosts.txt -top-ports 100 -cdn -scan-type c -verify -silent -j -o naabu.jsonl`

JSONL output includes a `cdn` field when a CDN is detected.

### Exclude CDN (`-ec, -exclude-cdn`)

Skips full port scans for CDN/WAF-hosted targets — scans only 80 and 443 (the only ports that reach the origin through the CDN). Non-CDN hosts are scanned normally.

`naabu -list hosts.txt -top-ports 1000 -ec -cdn -scan-type c -verify -silent -j -o naabu.jsonl`

### Workflow

1. Run with `-cdn` first to identify which hosts are behind CDNs.
2. Re-run with `-ec` to skip unnecessary port scanning on CDN hosts.
3. For CDN-hosted targets, focus on 80/443 and layer-7 testing (httpx → nuclei / ffuf / sqlmap).

---

## Stream Mode

`-stream` enables maximum-throughput scanning by disabling resume, verification, retries, and host shuffling. The scan fires probes as fast as the rate limit allows without bookkeeping overhead.

`naabu -list hosts.txt -top-ports 100 -stream -rate 5000 -c 200 -silent -o naabu_stream.txt`

### What stream mode disables

- **Resume:** no `resume.cfg` is written. An interrupted stream scan cannot be continued.
- **Verify:** no second-pass TCP verification. Results include false positives.
- **Retries:** no retries on failed probes. Transient packet loss becomes false negatives.
- **Shuffling:** hosts and ports are scanned in order. Predictable scan pattern — easier to detect and block.

### When to use

- Maximum-speed initial sweep across a large range where coverage > accuracy.
- The results will be verified in a follow-up pass anyway (e.g. piped to httpx).
- Time-boxed reconnaissance where scanning must finish within minutes.

### When to avoid

- When results feed directly into vulnerability scanners — false positives waste scanner time.
- When the target might block sequential scanning patterns.
- When you need resumability for long-running scans.

---

## nmap CLI Integration

`-nmap-cli <cmd>` passes discovered ports to nmap for deeper analysis. naabu runs the specified nmap command against each host with the discovered ports appended.

`naabu -host target.tld -top-ports 100 -scan-type c -verify -silent -nmap-cli 'nmap -sV -sC -oA nmap_out'`

naabu constructs the nmap invocation: `nmap -sV -sC -oA nmap_out -p <discovered_ports> <host>`.

### Use cases

- **Service version + script scan:** `-nmap-cli 'nmap -sV -sC'` — naabu finds ports fast, nmap does deep service analysis.
- **Vulnerability scripts:** `-nmap-cli 'nmap --script vuln'` — naabu discovers, nmap checks for known vulns.
- **UDP follow-up:** `-nmap-cli 'nmap -sU -sV --top-ports 20'` — naabu TCP discovers, nmap does targeted UDP on interesting hosts.
- **Output formats:** `-nmap-cli 'nmap -sV -oX nmap.xml'` — pipe naabu speed into nmap's rich XML output.

### Guidelines

- Always include `-verify` before `-nmap-cli` — false-positive ports waste nmap's time.
- nmap must be installed (it is in the sandbox at `/usr/bin/nmap`).
- The nmap command runs per host. For large target lists, this multiplies execution time — filter to interesting hosts first.
- The deprecated `-nmap` flag (boolean) invoked nmap with defaults; `-nmap-cli` replaced it with explicit control.

---

## Detection Profile

### SYN scan fingerprint

- Half-open connections: SYN sent, SYN-ACK received, RST sent without completing handshake. Stateful firewalls and IDS log this pattern.
- Raw packet characteristics: naabu's SYN packets have default TCP options (window size, MSS) that differ from OS-generated SYN packets. Some IDS rules match on these.
- No application-layer log entry — the connection never completes, so web server / SSH daemon logs stay clean.
- IDS signatures: Snort/Suricata rules for SYN scan detection fire on high SYN-to-established ratios from a single source.

### CONNECT scan fingerprint

- Full TCP handshakes appear in connection logs (web server access logs, firewall state tables, application audit logs).
- Immediate disconnect after handshake (unless `-cp` sends a payload). A pattern of connect-then-immediately-close across many ports is a scanning signature.
- The OS TCP stack generates the packets — no raw-packet fingerprint; indistinguishable from normal TCP at the packet level.
- Higher visibility to application-level logging than SYN scan.

### Rate profile

- Default `-rate 1000` is aggressive. On a /24 with `-top-ports 100`, that is 25,600 probes completing in ~25 seconds — a visible spike in any traffic monitoring.
- Sequential host/port ordering (without shuffling) creates a predictable sweep pattern in firewall logs.
- `-stream` mode's lack of shuffling makes the pattern even more uniform.

### Host discovery probe visibility

- ICMP probes (`-pe`, `-pp`, `-pm`): visible to any IDS monitoring ICMP; some networks alert on ICMP sweeps.
- TCP probes (`-ps`, `-pa`): look like normal connection attempts on the probed ports; less distinctive than ICMP sweeps.
- ARP probes: visible only on the LAN segment; not logged by most infrastructure unless ARP monitoring is enabled.

---

## Evasion

All evasion techniques are situational — they reduce scan visibility, not eliminate it. The goal is to avoid automated blocking and rate limiting, not to be invisible to a determined analyst.

### Scan type selection

- CONNECT scans blend with normal TCP traffic at the packet level. SYN scans avoid application logs but create a half-open fingerprint.
- For targets with application-level detection (WAF, RASP), CONNECT with `-cp` that sends a plausible payload (e.g. HTTP `GET / HTTP/1.0\r\n\r\n`) looks more like real traffic.

### Rate and timing

- Lower `-rate` (50-200) and `-c` (5-15) for stealthy scans.
- `-warm-up-time <sec>` adds delay between scan phases — prevents a burst at the start.
- `-retries 1` reduces repeated probes to the same port (each retry is another signature).

Low-and-slow baseline:
`naabu -host target.tld -top-ports 100 -scan-type c -rate 50 -c 10 -timeout 2000 -retries 1 -warm-up-time 5 -verify -silent -j -o naabu_slow.jsonl`

### Source IP and interface

- `-source-ip <x.x.x.x:port>` binds to a specific source address (SYN scan only). Useful when multiple interfaces are available or when spoofing source (requires appropriate network position).
- `-interface <iface>` binds to a specific NIC. Use on multi-homed hosts to control which network path the scan takes.

### CDN exclusion

`-ec` prevents full port scanning of CDN-hosted targets. Beyond accuracy, this avoids triggering CDN-side rate limiting and IP reputation penalties that would affect subsequent testing.

### Proxy routing

`-proxy socks5://host:port` tunnels CONNECT scans through a SOCKS5 proxy. Source-IP attribution shifts to the proxy. `-proxy-auth user:pass` for authenticated proxies.

Proxy adds latency — lower `-rate` and raise `-timeout` accordingly.

### DNS control

`-dns-order` controls whether naabu resolves hostnames via its probe mechanism (`p`), the local system resolver (`l`), or combinations (`lp`, `pl`). Using `-dns-order p` with custom resolvers (`-r`) avoids DNS queries to the local resolver that might log or leak target information.

### Host discovery probe selection

On filtered networks, choose probes that the specific firewall rules permit:
- Firewalls blocking ICMP: use `-ps`/`-pa` instead of `-pe`.
- Firewalls blocking inbound SYN: use `-pa` (ACK probes bypass stateful SYN filters).
- Internal network: use `-arp` (layer 2, not firewall-filtered).

---

## Resume and Session Management

`-resume` reads `resume.cfg` from the current working directory and continues an interrupted scan from where it stopped.

Workflow:
1. Start a scan: `naabu -list hosts.txt -top-ports 1000 -scan-type c -verify -silent -o results.txt`
2. Interrupt (Ctrl-C). naabu writes `resume.cfg` with scan progress.
3. Resume: `naabu -resume` — picks up remaining hosts/ports.

Notes:
- `resume.cfg` is JSON with scan state. Do not edit it manually.
- `-stream` mode disables resume — no state file is written.
- Resume uses the original scan parameters from the config. No flags are needed beyond `-resume`.
- Only one `resume.cfg` can exist per directory. If running multiple scans, use separate directories.

---

## Output and Automation

### Output formats

- **Plain text** (default): `host:port`, one per line. Grep-friendly, suitable for piping.
- **JSONL** (`-j`): one JSON object per line with structured fields (`host`, `ip`, `port`, and optionally `cdn`, `service`, `version`). Best for automation.
- **CSV** (`-csv`): comma-separated fields. Best for spreadsheet import or database loading.

### Field control

- `-lof, -list-output-fields` lists available output fields and exits. Useful for discovering which fields `-eof` can exclude.
- `-eof, -exclude-output-fields <fields>` removes fields from output. Example: `-eof cdn,timestamp` drops CDN and timestamp columns from CSV/JSONL.

### Parsing JSONL output

Extract open ports per host:
`jq -r '"\(.host):\(.port)"' naabu.jsonl`

Group ports by host:
`jq -r '.host' naabu.jsonl | sort -u | while read h; do echo "$h: $(jq -r "select(.host==\"$h\") | .port" naabu.jsonl | paste -sd,)"; done`

Filter to a specific port:
`jq -r 'select(.port == 443) | .host' naabu.jsonl`

Extract service versions:
`jq -r 'select(.version != null) | "\(.host):\(.port) \(.service) \(.version)"' naabu.jsonl`

### Feeding downstream tools

naabu plain-text output → httpx:
`naabu -list hosts.txt -top-ports 100 -scan-type c -verify -silent | httpx -silent -sc -title -td -o httpx.txt`

naabu JSONL → targeted nuclei:
`jq -r '"\(.host):\(.port)"' naabu.jsonl | httpx -silent | nuclei -as -s critical,high -o nuclei.txt`

---

## Tool-to-Tool Chaining

### Upstream — host/subdomain feeds

subfinder → naabu (subdomain discovery → port scan):
`subfinder -d target.tld -all -silent | naabu -scan-type c -top-ports 100 -rate 300 -verify -silent -j -o naabu.jsonl`

subfinder → dnsx → naabu (resolve first, scan live only):
`subfinder -d target.tld -all -silent | dnsx -silent | naabu -scan-type c -top-ports 100 -rate 300 -verify -silent -j -o naabu.jsonl`

nmap host discovery → naabu (nmap for host discovery, naabu for fast port scan):
`nmap -sn -oG - 10.0.0.0/24 | grep 'Up' | awk '{print $2}' | naabu -scan-type c -top-ports 100 -rate 500 -verify -silent -o naabu.txt`

### Downstream — port results feeding

naabu → httpx (HTTP service detection):
`naabu -list hosts.txt -top-ports 100 -verify -silent | httpx -silent -sc -title -server -td -j -o httpx.jsonl`

naabu → httpx → nuclei (full pipeline: port → HTTP → vuln scan):
`naabu -list hosts.txt -top-ports 100 -verify -silent | httpx -silent | nuclei -as -s critical,high -o nuclei.txt`

naabu → httpx → wafw00f (port → HTTP → WAF fingerprint):
`naabu -list hosts.txt -p 80,443,8080,8443 -verify -silent | httpx -silent -o live_http.txt && wafw00f -i live_http.txt -a -f json -o wafw00f.json`

naabu → httpx → katana → nuclei (port → HTTP → crawl → vuln):
`naabu -list hosts.txt -top-ports 100 -verify -silent | httpx -silent | katana -d 3 -jc -silent | nuclei -as -o nuclei_crawled.txt`

naabu + nmap-cli (port discovery → deep nmap):
`naabu -host target.tld -top-ports 1000 -verify -silent -nmap-cli 'nmap -sV -sC -oX nmap_deep.xml'`

naabu → ffuf (port-based vhost discovery):
`naabu -host target.tld -p 80,443,8080,8443 -verify -silent -j | jq -r '"\(.host):\(.port)"' | while read hp; do ffuf -u "http://$hp" -H "Host: FUZZ.target.tld" -w vhosts.txt -mc 200 -ac; done`

### Full reconnaissance pipeline

```
subfinder -d target.tld -all -silent -o subs.txt
cat subs.txt | dnsx -silent | naabu -scan-type c -top-ports 100 -ec -cdn -rate 300 -verify -silent -j -o naabu.jsonl
jq -r '"\(.host):\(.port)"' naabu.jsonl | httpx -silent -sc -title -td -j -o httpx.jsonl
httpx -l <(jq -r '.url' httpx.jsonl) -silent | nuclei -as -s critical,high -o nuclei.txt
```

---

## Routed Consumers

- `reconnaissance/*` — port/service enumeration is attack-surface mapping
- `vulnerabilities/*` — discovered services feed every service-specific vulnerability class
- `tooling/httpx.md` — primary downstream consumer of `host:port` pairs
- `tooling/nuclei.md` — vulnerability scanning against discovered services
- `tooling/nmap.md` — deep service/script analysis via `-nmap-cli` or as follow-up
- `tooling/wafw00f.md` — WAF fingerprinting on discovered HTTP services
- `tooling/katana.md` — crawling discovered web services
- `tooling/ffuf.md` — fuzzing endpoints on discovered ports
- `tooling/subfinder.md` — upstream subdomain discovery feeding naabu
- `tooling/dnsx.md` — DNS resolution/filtering between subfinder and naabu
- `tooling/tlsx.md` — TLS/certificate analysis on discovered HTTPS ports
