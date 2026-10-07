---
name: nmap
description: Canonical Nmap CLI syntax, two-pass scanning workflow, and sandbox-safe bounded scan patterns.
---

# Nmap CLI Playbook

Official docs:
- https://nmap.org/book/man-briefoptions.html
- https://nmap.org/book/man.html
- https://nmap.org/book/man-performance.html
- https://nmap.org/nsedoc/

Canonical syntax:
`nmap [Scan Type(s)] [Options] {target specification}`

High-signal flags:
- `-n` skip DNS resolution
- `-Pn` skip host discovery when ICMP/ping is filtered
- `-sS` SYN scan (root/privileged)
- `-sT` TCP connect scan (no raw-socket privilege)
- `-sV` detect service versions
- `-sC` run default NSE scripts
- `-p <ports>` explicit ports (`-p-` for all TCP ports)
- `--top-ports <n>` quick common-port sweep
- `--open` show only hosts with open ports
- `-T<0-5>` timing template (`-T4` common)
- `--max-retries <n>` cap retransmissions
- `--host-timeout <time>` give up on very slow hosts
- `--script-timeout <time>` bound NSE script runtime
- `-oA <prefix>` output in normal/XML/grepable formats
- `-A` enable OS detection, version detection, script scanning, and traceroute
- `-6` enable IPv6 scanning
- `--reason` display port state reason (syn-ack, rst, no-response, etc.)
- `-iL <file>` input target list from file

Agent-safe baseline for automation:
`nmap -n -Pn --open --top-ports 100 -T4 --max-retries 1 --host-timeout 90s -oA nmap_quick <host>`

Common patterns:
- Fast first pass:
  `nmap -n -Pn --top-ports 100 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Very small important-port pass:
  `nmap -n -Pn -p 22,80,443,8080,8443 --open -T4 --max-retries 1 --host-timeout 90s <host>`
- Service/script enrichment on discovered ports:
  `nmap -n -Pn -sV -sC -p <comma_ports> --script-timeout 30s --host-timeout 3m -oA nmap_services <host>`
- No-root fallback:
  `nmap -n -Pn -sT --top-ports 100 --open --host-timeout 90s <host>`
- Full TCP + version + OS on known ports:
  `nmap -n -Pn -sS -sV -O -p <comma_ports> --osscan-guess --version-intensity 5 --host-timeout 5m -oA nmap_full <host>`
- UDP top-port sweep:
  `nmap -n -Pn -sU --top-ports 20 --open -T4 --host-timeout 2m -oA nmap_udp <host>`
- Vulnerability scan on discovered services:
  `nmap -n -Pn --script vuln -p <comma_ports> --script-timeout 60s --host-timeout 5m -oA nmap_vuln <host>`

Critical correctness rules:
- Always set target scope explicitly.
- Prefer two-pass scanning: discovery pass, then enrichment pass.
- Always set a timeout boundary with `--host-timeout`; add `--script-timeout` whenever NSE scripts are involved.
- Keep discovery scans tight: use explicit important ports or a small `--top-ports` profile unless broader coverage is explicitly required.
- In sandboxed runs, avoid exhaustive sweeps (`-p-`, very high `--top-ports`, or wide host ranges) unless explicitly required.
- Do not spam traffic; start with the smallest port set that can answer the question.
- Prefer `naabu` for broad port discovery; use `nmap` for scoped verification/enrichment.

Usage rules:
- Add `-n` by default in automation to avoid DNS delays.
- Use `-oA` for reusable artifacts.
- Prefer `-p 22,80,443,8080,8443` or `--top-ports 100` before considering larger sweeps.
- Do not use `-h`/`--help` for routine usage unless absolutely necessary.

Failure recovery:
- If host appears down unexpectedly, rerun with `-Pn`.
- If scan stalls, tighten scope (`-p` or smaller `--top-ports`) and lower retries.
- If scripts run too long, add `--script-timeout`.
- If unprivileged, fall back from `-sS` to `-sT`.
- If UDP scan never finishes, reduce to `--top-ports 10` and add `--max-retries 0`.

If uncertain, query web_search with:
`site:nmap.org/book nmap <flag>`

---

## Target Specification

Nmap accepts hostnames, IP addresses, CIDR ranges, octet ranges, and lists:
- Single host: `192.168.1.1` or `target.tld`
- CIDR: `192.168.1.0/24`
- Octet range: `10.0.0-255.1-254`
- From file: `-iL targets.txt` (one target per line)
- Exclude hosts: `--exclude 192.168.1.1,192.168.1.2` or `--excludefile skip.txt`
- Random targets: `-iR <count>` (research/internet-scale only)

Port specification:
- Explicit: `-p 22,80,443` or `-p 1-1024`
- All TCP: `-p-` (equivalent to `-p 1-65535`)
- Protocol-qualified: `-p U:53,111,T:21-25,80,S:9` (UDP, TCP, SCTP)
- Top ports: `--top-ports 1000` (by frequency from nmap-services)
- Port ratio: `--port-ratio 0.01` (ports more common than 1%)
- Fast mode: `-F` (top 100 ports)
- Exclude ports: `--exclude-ports 9100` (skip noisy ports like PJL)
- Sequential: `-r` (don't randomize port order; useful when debugging or timing)

---

## Scan Techniques

Each technique sends different packet types and interprets different responses. Choose by context — what you need to learn, what privilege you have, and what the target's filtering looks like.

**TCP SYN scan (`-sS`)** — the default for privileged users. Sends SYN, reads SYN/ACK (open) or RST (closed), never completes the handshake. Fast, relatively quiet, and the standard choice for port discovery.

**TCP connect scan (`-sT`)** — uses the OS `connect()` call. No raw-socket privilege required. Completes the full three-way handshake, so it's logged by any application-level connection logging. Use when running unprivileged or when `-sS` is blocked.

**TCP ACK scan (`-sA`)** — sends only ACK packets. Cannot determine open vs. closed; determines *filtered vs. unfiltered*. Use to map firewall rulesets — an RST response means the port is unfiltered (the packet passed the firewall); no response means filtered.
`nmap -n -Pn -sA -p <ports> --host-timeout 90s <host>`

**TCP Window scan (`-sW`)** — like ACK scan but examines the TCP window size in RST responses. On some stacks, open ports return a positive window size while closed ports return zero. OS-dependent; verify against known-open ports before trusting.

**TCP Maimon scan (`-sM`)** — sends FIN/ACK. Some BSD-derived stacks drop the packet for open ports instead of responding with RST. Rarely useful on modern stacks.

**TCP Null, FIN, Xmas scans (`-sN`, `-sF`, `-sX`)** — exploit RFC 793: a closed port must respond with RST to a packet lacking SYN/RST/ACK flags, while an open port should drop it silently. Null sends no flags, FIN sends FIN only, Xmas sends FIN/PSH/URG. Ineffective against Windows (responds RST to everything regardless) and filtered ports (no response either way). Occasionally useful to bypass stateless firewalls that only inspect SYN.
`nmap -n -Pn -sN -p <ports> --host-timeout 90s <host>`

**Custom scan flags (`--scanflags`)** — set arbitrary TCP flag combinations. Accepts numeric value or flag names: `--scanflags SYNFIN`, `--scanflags URGACKPSHRSTSYNFIN`, `--scanflags 0x03`. Combine with a scan type to control response interpretation: `nmap --scanflags SYNFIN -sS <host>` uses SYN scan response logic on SYN+FIN packets.

**UDP scan (`-sU`)** — sends UDP probes. Open ports often don't respond; closed ports return ICMP port unreachable. Inherently slow — ICMP rate limiting on most hosts caps throughput. Keep port set small:
`nmap -n -Pn -sU --top-ports 20 -T4 --max-retries 0 --host-timeout 2m <host>`

Combine UDP and TCP in a single run: `nmap -sS -sU -p T:80,443,U:53,161 <host>`

**SCTP INIT scan (`-sY`)** — analogous to SYN scan for SCTP. Sends INIT chunk; INIT-ACK means open, ABORT means closed.

**SCTP COOKIE-ECHO scan (`-sZ`)** — sends COOKIE-ECHO chunk. Open ports drop it silently (per RFC); closed ports respond with ABORT. Can bypass non-stateful firewalls.

**IP protocol scan (`-sO`)** — determines which IP protocols (TCP, ICMP, IGMP, etc.) a host supports. Not a port scan; iterates protocol numbers.

**Idle scan (`-sI`)** — completely stealthy; uses a "zombie" host's IP ID sequence to infer port state without sending any packets from your own IP. Requires a zombie with predictable incremental IP IDs and no significant traffic:
`nmap -sI <zombie_host> -p <ports> <target>`
Verify zombie suitability first: `nmap -O -v <zombie_candidate>` and check for incremental IP ID.

**FTP bounce scan (`-b`)** — uses an FTP server's PORT command to scan through it. Historically significant; most modern FTP servers block it.

---

## Host Discovery

Before port scanning, nmap determines which hosts are alive. Discovery behavior depends on privilege and target:

Default privileged discovery (LAN): ARP ping.
Default privileged discovery (remote): ICMP echo + TCP SYN to 443 + TCP ACK to 80 + ICMP timestamp.
Default unprivileged: TCP connect to 80 and 443.

Override with explicit probes:
- `-Pn` — skip discovery entirely; treat all hosts as up. Required when ICMP/ping is filtered and you know the host exists. The most common override.
- `-sn` — ping scan only; skip port scan. Use for host enumeration:
  `nmap -sn 10.0.0.0/24`
- `-PS <portlist>` — TCP SYN discovery. Send SYN to specified ports; SYN/ACK or RST = host up:
  `nmap -PS22,80,443 -sn 10.0.0.0/24`
- `-PA <portlist>` — TCP ACK discovery. Penetrates stateless firewalls that block SYN:
  `nmap -PA80,443 -sn 10.0.0.0/24`
- `-PU <portlist>` — UDP discovery. Closed UDP port returns ICMP unreachable = host up:
  `nmap -PU53,161 -sn 10.0.0.0/24`
- `-PY <portlist>` — SCTP discovery.
- `-PE` — ICMP echo (classic ping). `-PP` — ICMP timestamp. `-PM` — ICMP address mask.
- `-PO <protocol list>` — IP protocol ping. Sends packets with specified protocol numbers.

Combine probes for maximum reach: `nmap -PE -PS22,80,443 -PA80 -PU53 -sn <range>`

DNS control:
- `-n` — never resolve; fastest, default for automation.
- `-R` — always resolve.
- `--dns-servers 8.8.8.8,1.1.1.1` — use custom resolvers.
- `--system-dns` — use OS resolver instead of nmap's built-in.

`--traceroute` — trace hop path to each host. Runs after the scan.

List scan (`-sL`) — list targets without sending any packets; useful to verify your target spec before scanning:
`nmap -sL 10.0.0.0/24`

---

## Service and Version Detection

`-sV` probes open ports to identify service name, version, and sometimes OS. Nmap sends protocol-specific probes from its `nmap-service-probes` database and matches responses.

Intensity controls what probes are sent:
- `--version-intensity <0-9>` — higher values try more probes. Default is 7.
- `--version-light` — intensity 2; fast, catches common services.
- `--version-all` — intensity 9; tries every probe; slow but thorough.
- `--version-trace` — show detailed probe/response activity for debugging.

Practical guidance:
- Start with default intensity. Drop to `--version-light` on large scans for speed.
- Escalate to `--version-all` on individual interesting ports that default intensity misclassifies.
- Version detection is active probing — it generates application-layer traffic (HTTP requests, TLS handshakes, banner grabs) that is logged by the service.
- `-sV` implicitly enables banner grabbing; the initial probe is often a TCP connection that reads the service banner.

Version detection output includes: service name, version number (when identifiable), extra info (OS, hostname, device type), and CPE (Common Platform Enumeration) identifiers useful for correlation with vulnerability databases.

Combined with NSE default scripts:
`nmap -sV -sC -p <ports> <host>` — enriches both version and script output. The `version` NSE category (47 scripts) runs automatically during `-sV`.

---

## OS Detection

`-O` enables OS fingerprinting by analyzing TCP/IP stack behavior — initial TTL, window size, DF bit, TCP options ordering, and responses to unusual probes.

Flags:
- `-O` — enable OS detection.
- `--osscan-limit` — only attempt OS detection on hosts with at least one open and one closed TCP port (required for reliable fingerprinting).
- `--osscan-guess` — guess more aggressively; print low-confidence matches.

Reliability: OS detection requires at least one open and one closed port to generate a full fingerprint. Firewalled hosts that filter all closed ports produce incomplete fingerprints. `-Pn -O` on a fully filtered host often yields "too many fingerprints match" or no match.

`-A` is a convenience alias that enables `-O`, `-sV`, `-sC`, and `--traceroute` together:
`nmap -A -p <ports> --host-timeout 5m -oA nmap_aggressive <host>`

OS detection output includes: OS family, generation, CPE, and accuracy percentage. Multiple matches are listed with decreasing confidence. Cross-reference with `-sV` version data for higher-fidelity identification — version strings often reveal more about the exact OS release than TCP/IP fingerprinting alone.

Aggressive guessing with match thresholds:
`nmap -O --osscan-guess -p 22,80,443 <host>` — prints matches even at low confidence, tagged with "aggressive OS guesses" and a percentage.

---

## NSE Scripting Engine

The NSE transforms nmap from a port scanner into a scriptable reconnaissance and vulnerability assessment platform. 612 scripts ship with nmap 7.99 across 13 categories.

### Running scripts

- `-sC` — equivalent to `--script=default` (123 scripts in the default category).
- `--script <spec>` — run specified scripts. Spec can be:
  - A category: `--script vuln`
  - A script name: `--script http-enum`
  - A path: `--script /path/to/custom.nse`
  - A comma-separated list: `--script http-enum,http-headers,ssl-cert`
  - A wildcard: `--script "http-*"`
  - A boolean expression: `--script "vuln and not dos"`, `--script "(default or safe) and not broadcast"`

- `--script-args=<n1=v1,[n2=v2,...]>` — pass arguments to scripts:
  `--script-args userdb=users.txt,passdb=pass.txt`
- `--script-args-file=<file>` — load script args from file.
- `--script-trace` — show all data sent and received by scripts (verbose).
- `--script-timeout <time>` — per-script timeout; essential for automation:
  `--script-timeout 30s`
- `--script-updatedb` — rebuild the script database after adding custom scripts.
- `--script-help=<spec>` — show help for specified scripts:
  `nmap --script-help "http-*"`

### Categories and high-value scripts

**vuln** (104 scripts) — detect known vulnerabilities:
- `ssl-heartbleed` — CVE-2014-0160
- `smb-vuln-ms17-010` — EternalBlue
- `smb-vuln-ms08-067` — Conficker vector
- `http-shellshock` — CVE-2014-6271
- `http-vuln-cve2017-5638` — Apache Struts RCE
- `http-iis-webdav-vuln` — IIS WebDAV
- `http-csrf`, `http-dombased-xss`, `http-stored-xss` — web vuln detection
- `http-sql-injection` — reflected SQL injection testing
- `http-passwd` — path traversal for /etc/passwd
- `vulners` — correlates version info with the vulners.com CVE database

Run all vuln scripts on known ports:
`nmap -n -Pn --script vuln -p <ports> --script-timeout 60s --host-timeout 5m -oA nmap_vuln <host>`

Run specific vuln checks: `nmap --script ssl-heartbleed,smb-vuln-ms17-010 -p 443,445 <host>`

**exploit** (45 scripts) — actively exploit vulnerabilities:
- `http-shellshock` (also in vuln)
- `http-fileupload-exploiter` — attempt file upload exploitation
- `ftp-vsftpd-backdoor` — test for vsftpd 2.3.4 backdoor
- `http-majordomo2-dir-traversal`
- `distcc-cve2004-2687` — distcc RCE

**brute** (70 scripts) — credential brute-forcing:
- `ssh-brute`, `ftp-brute`, `http-brute`, `http-form-brute`
- `smb-brute`, `ldap-brute`, `snmp-brute`, `mysql-brute`
- `smtp-enum-users` — VRFY/EXPN/RCPT enumeration
- Control wordlists: `--script-args userdb=users.txt,passdb=pass.txt`
- Control parallelism: `--script-args brute.threads=5`

**discovery** (307 scripts) — enumerate services and information:
- `http-enum` — web directory/file enumeration
- `http-methods` — detect allowed HTTP methods (PUT, DELETE, etc.)
- `http-robots.txt` — parse robots.txt
- `http-config-backup` — look for config backup files
- `http-vhosts` — virtual host discovery
- `http-git` — detect exposed .git
- `http-title` — grab page title
- `http-headers` — dump response headers
- `http-default-accounts` — test default credentials for known products
- `smb-enum-shares`, `smb-os-discovery` — SMB enumeration
- `dns-zone-transfer`, `dns-brute` — DNS enumeration
- `mysql-info`, `mysql-enum`, `ms-sql-info`, `mongodb-info`, `redis-info`
- `rdp-enum-encryption` — RDP security assessment

**auth** (38 scripts) — authentication testing:
- `ssh-auth-methods` — enumerate allowed SSH auth methods
- `ftp-anon` — test anonymous FTP
- `http-cookie-flags` — check Secure/HttpOnly
- `http-cross-domain-policy` — check crossdomain.xml

**safe** (347 scripts) — information gathering that shouldn't cause disruption.

**default** (123 scripts) — reasonable enrichment for general scanning; what `-sC` runs.

**version** (47 scripts) — augment `-sV` version detection.

**broadcast** (47 scripts) — send broadcast queries to discover hosts/services on the local network:
`nmap --script broadcast -e eth0`

**external** (32 scripts) — query external services (DNS, WHOIS, vulners.com). May leak target info to third parties.

**dos** (11 scripts) — denial-of-service testing. Excluded from safe/default. Use with care:
`--script "vuln and not dos"`

**malware** (9 scripts) — detect backdoors and malware indicators.

**intrusive** (208 scripts) — may crash services or trigger IDS. Not in default; run deliberately.

**fuzzer** (3 scripts) — send unexpected data to find bugs.

### Script arguments for common scenarios

HTTP authentication for scripts:
`--script-args http.useragent="Mozilla/5.0",http.pipeline=10`

HTTP basic auth:
`--script-args http.auth="user:pass"`

TLS/SSL controls:
`--script-args ssl.cert=/path/to/cert.pem`

### Targeted script combinations

**Web application recon** — enumerate surface before manual testing:
`nmap -sV --script "http-enum,http-methods,http-headers,http-title,http-robots.txt,http-git,http-config-backup,http-cookie-flags,http-default-accounts" -p 80,443,8080,8443 --script-timeout 30s <host>`

**SSL/TLS assessment** — enumerate cipher suites, certificate details, and known TLS vulns:
`nmap --script "ssl-enum-ciphers,ssl-cert,ssl-heartbleed" -p 443,8443,993,995,465 <host>`
The `ssl-enum-ciphers` output grades each cipher suite (A through F); look for weak ciphers and deprecated protocols.

**Database enumeration** — service-specific recon on common DB ports:
`nmap -sV --script "mysql-info,mysql-enum,ms-sql-info,mongodb-info,redis-info" -p 3306,1433,27017,6379 --script-timeout 15s <host>`

**SMB deep enumeration** — shares, users, OS, and vuln checks:
`nmap --script "smb-os-discovery,smb-enum-shares,smb-enum-users,smb-vuln-*" -p 445 <host>`

**DNS intelligence** — zone transfer and brute-force:
`nmap --script "dns-zone-transfer,dns-brute" --script-args dns-brute.threads=10 -p 53 <dns_server>`

**Brute-force with controlled parallelism:**
`nmap --script ssh-brute --script-args brute.threads=3,userdb=users.txt,passdb=top100.txt -p 22 --script-timeout 5m <host>`

### Boolean script selection

Combine categories and script names with boolean logic:
- `--script "default and safe"` — scripts in both categories.
- `--script "vuln and not dos"` — vulnerability checks that don't risk DoS.
- `--script "(http-* or ssl-*) and not intrusive"` — HTTP and SSL recon without intrusive tests.
- `--script "auth or default"` — auth checks plus defaults.

---

## Timing and Performance

### Timing templates

`-T<0-5>` sets a timing profile controlling parallelism, probe timeout, and inter-probe delay:

- `-T0` (paranoid) — serial, 5-minute inter-probe delay. IDS evasion; extremely slow.
- `-T1` (sneaky) — serial, 15-second delay. Low-and-slow; avoids most rate-based IDS.
- `-T2` (polite) — serial, 0.4-second delay. Reduces target load.
- `-T3` (normal) — default. Balanced speed and reliability.
- `-T4` (aggressive) — recommended for reliable networks. Caps RTT timeout at 1250ms, max retries at 6. Standard for pentesting.
- `-T5` (insane) — maximum speed. Caps RTT at 300ms, max retries at 2. Drops accuracy on lossy networks.

### Granular timing controls

Override individual parameters when templates are too coarse:

Parallelism:
- `--min-hostgroup <n>` / `--max-hostgroup <n>` — group size for parallel host scanning. Higher values scan more hosts concurrently but delay per-host results until the group completes. `--min-hostgroup 64` for large subnets.
- `--min-parallelism <n>` / `--max-parallelism <n>` — number of probes outstanding simultaneously. `--min-parallelism 100` for faster scanning; `--max-parallelism 1` for stealth.

RTT tuning:
- `--initial-rtt-timeout <time>` — starting RTT estimate before adaptive tuning kicks in. Default is calibrated from the first few probes; override for known-latency targets.
- `--min-rtt-timeout <time>` / `--max-rtt-timeout <time>` — bounds on RTT. Lower `--max-rtt-timeout` to avoid long waits on filtered ports: `--max-rtt-timeout 500ms`.

Rate control:
- `--min-rate <n>` — send at least `n` packets/second. Forces speed on slow scans.
- `--max-rate <n>` — cap at `n` packets/second. Throttle to avoid detection or target overload: `--max-rate 50`.

Delays:
- `--scan-delay <time>` — minimum delay between probes to a single host. Overrides timing template. `--scan-delay 1s` for throttled scanning.
- `--max-scan-delay <time>` — cap the delay nmap's adaptive algorithm can grow to.

Retries and timeouts:
- `--max-retries <n>` — cap retransmissions. `--max-retries 1` for fast scans; `--max-retries 0` accepts first-pass results only.
- `--host-timeout <time>` — give up on a host entirely after this duration. Essential for automation: `--host-timeout 5m`.

Tuning for stealth vs. speed:
- Stealth: `-T1 --max-parallelism 1 --scan-delay 5s --max-rate 5`
- Speed: `-T4 --min-hostgroup 64 --min-parallelism 100 --max-retries 1 --host-timeout 90s`
- Balanced: `-T4 --max-retries 2 --host-timeout 3m --max-rate 200`

---

## Firewall and IDS Evasion

Nmap provides extensive evasion capabilities. Effectiveness is situational — modern stateful firewalls and NGIPS defeat many techniques that worked against older packet filters. Test against the specific environment; never assume a technique guarantees evasion.

### Nmap's detection fingerprint

By default, nmap is identifiable by:
- Rapid sequential port probing from a single source IP.
- Default TCP window sizes and TTL values in crafted packets.
- IP ID sequencing patterns in probe packets.
- Timing patterns (burst of probes, then pause for retransmissions).
- NSE script HTTP User-Agent: `Mozilla/5.0 (compatible; Nmap Scripting Engine; ...)`.
- Specific TCP option sequences in OS fingerprinting probes.

IDS systems detect port scans through statistical analysis (many ports probed from one IP in a time window) rather than individual packet signatures.

### Packet fragmentation

`-f` — fragment IP packets into 8-byte fragments, splitting TCP headers across multiple fragments. Some older packet filters and IDS cannot reassemble fragments before inspection.

`--mtu <val>` — set a specific MTU for fragmentation. Must be a multiple of 8. `--mtu 16` sends 16-byte fragments. Smaller fragments = more evasion potential but more packets and slower scanning.

Effectiveness: situational. Modern NGIPS reassemble fragments before inspection. Older/simpler packet filters and IDS appliances may still be defeated. Fragmentation can also bypass some network-level firewalls that only inspect the first fragment.

### Decoy scanning

`-D <decoy1,decoy2[,ME],...>` — send identical scans from spoofed source IPs alongside your real scan. The target and any monitoring sees probes from multiple sources, obscuring which is real.

`nmap -D RND:5,ME -p 80,443 <host>` — use 5 random decoy IPs plus your real IP.
`nmap -D 10.0.0.2,10.0.0.3,ME,10.0.0.5 -p 80,443 <host>` — explicit decoys with your IP third.

`ME` specifies your position in the decoy list; randomize it. Omit `ME` and nmap places you randomly.

Effectiveness: decoys obscure the scanner's identity in logs but don't hide that a scan occurred. The target sees all the scan traffic. Decoy IPs should be alive — responses to dead IPs reveal them as decoys. Does not work with `-sT` (connect scan) or `-sV`.

### Source address and port manipulation

`-S <IP>` — spoof source address. Requires `-e <iface>` to specify the interface. You won't receive responses (they go to the spoofed IP), so useful only with idle scan or for firewall rule testing.

`-g <port>` / `--source-port <port>` — set source port. Stateless firewalls and misconfigured ACLs sometimes permit traffic from specific source ports:
- `-g 53` — impersonate DNS; some firewalls allow TCP/UDP from port 53.
- `-g 80` — impersonate HTTP return traffic.
- `-g 88` — impersonate Kerberos.

`nmap -g 53 -sS -p <ports> <host>`

Effectiveness: bypasses only stateless or misconfigured rules. Stateful firewalls track connection state and are not fooled by source port alone.

### Proxy routing

`--proxies <url1,[url2],...>` — relay connections through HTTP/SOCKS4 proxies. Works with `-sT` (connect scan) only. Multiple proxies are chained in order.

`nmap --proxies socks4://proxy:1080 -sT -p 80,443 <host>`

Limitations: TCP connect scan only; no SYN/UDP/OS detection through proxies. Adds latency.

### Payload manipulation

- `--data <hex string>` — append custom hex payload: `--data 0xdeadbeef`
- `--data-string <string>` — append ASCII string to packets: `--data-string "probe"`
- `--data-length <num>` — append `num` bytes of random data. Changes packet size to evade length-based signatures: `--data-length 50`
- `--ip-options <options>` — set IP header options (loose/strict source routing, record route, timestamp). Some firewalls drop packets with IP options.

### TTL and MAC manipulation

`--ttl <val>` — set IP TTL. Lower TTL can reach nearby targets while expiring before distant IDS sensors. TTL analysis can also reveal firewall hop count.

`--spoof-mac <mac>` — spoof source MAC address. Accepts full address, OUI prefix, or vendor name: `--spoof-mac Apple`, `--spoof-mac 00:11:22:33:44:55`, `--spoof-mac 0`. Works only on local network (same broadcast domain). `0` generates a completely random MAC.

### Bad checksums

`--badsum` — send packets with intentionally wrong TCP/UDP/SCTP checksums. Real hosts drop bad-checksum packets. Some firewalls/IDS devices don't verify checksums and respond anyway — a response indicates a middlebox, not the real host. Useful for firewall detection, not scanning.

### Custom scan flags

`--scanflags <flags>` — set arbitrary TCP flags. Combine with evasion to craft packets that bypass specific filter rules:
`nmap --scanflags SYNFIN -p 80 <host>` — SYN+FIN may bypass some firewalls that only check for SYN-only packets.

### Evasion combinations

Layer techniques for harder attribution:
`nmap -sS -T2 -f --data-length 24 -g 53 -D RND:3,ME --max-rate 10 --scan-delay 500ms -p 80,443 <host>`

For NSE script evasion, control the HTTP User-Agent:
`--script-args http.useragent="Mozilla/5.0 (Windows NT 10.0; Win64; x64)"`

### Firewall rule mapping with ACK scan

Use ACK scan to map which ports are filtered vs. unfiltered:
`nmap -sA -p 1-1024 -T4 <host>`

Unfiltered ports (RST response) indicate the firewall passes traffic to that port. Filtered ports (no response/ICMP unreachable) are blocked. Compare with SYN scan results — a port that is "unfiltered" via ACK but "filtered" via SYN suggests a stateful firewall blocking new connections.

### Network interface and routing

`--iflist` — print host interfaces and routes. Useful for understanding which interface nmap will use.
`-e <iface>` — force a specific interface.
`--send-eth` — send using raw ethernet frames (default on most platforms).
`--send-ip` — send using raw IP packets instead of ethernet frames.

### IPv6

`-6` enables IPv6 scanning. All scan types work; target must be an IPv6 address or a hostname resolving to AAAA:
`nmap -6 -sS -sV -p 80,443 <ipv6_addr>`
IPv6 scanning is often less filtered than IPv4 — firewalls may not apply the same rules to IPv6 traffic.

### Privileged vs. unprivileged

`--privileged` — assume full privilege even if nmap can't detect it (needed in some container environments).
`--unprivileged` — force unprivileged mode (connect scan only).

In Docker containers without `--cap-add NET_RAW`, nmap falls back to `-sT` automatically. The sandbox image wrapper may block raw sockets; use `-sT` as fallback.

---

## Output Formats and Parsing

### Format flags

- `-oN <file>` — normal human-readable output.
- `-oX <file>` — XML output. The richest format; includes all scan data, OS fingerprints, script output, timing stats. Parseable with xmlstarlet, xmllint, or Python's xml.etree.
- `-oG <file>` — grepable output. One line per host; easy to parse with grep/awk/cut.
- `-oS <file>` — script kiddie output. Novelty; not useful.
- `-oA <basename>` — output in normal, XML, and grepable simultaneously. Creates `<basename>.nmap`, `<basename>.xml`, `<basename>.gnmap`.

Always use `-oA` in automation for reproducibility.

### Output control flags

- `--open` — show only open/possibly-open ports. Dramatically reduces noise in results.
- `--reason` — show why each port is in its state (syn-ack, rst, no-response, etc.). Essential for understanding filtered vs. closed behavior.
- `-v` / `-vv` — increase verbosity. `-vv` shows script output details and scan progress.
- `-d` / `-dd` — debug output. Shows packet-level details; useful for diagnosing evasion.
- `--packet-trace` — show all packets sent and received. Heavy output; use for targeted debugging.
- `--append-output` — append to existing output files instead of overwriting.
- `--noninteractive` — disable runtime keyboard controls. Required in automation where stdin may not be a terminal.
- `--resume <file>` — resume an interrupted scan from a normal-output file (`-oN` or `-oA`). Nmap logs enough state to continue where it stopped.

### Parsing grepable output

Extract open ports per host:
`grep 'Ports:' scan.gnmap | grep 'open' | cut -d' ' -f2,4-`

Extract hosts with a specific open port:
`grep '80/open' scan.gnmap | cut -d' ' -f2`

Build a port list from grepable output for follow-up:
`grep 'Ports:' scan.gnmap | grep -oP '\d+/open' | cut -d/ -f1 | sort -un | paste -sd,`

### Parsing XML output

Extract open ports with xmlstarlet:
`xmlstarlet sel -t -m '//port[state/@state="open"]' -v '@portid' -n scan.xml`

Extract host/port/service table:
`xmlstarlet sel -t -m '//host' -v 'address/@addr' -o $'\t' -m 'ports/port[state/@state="open"]' -v '@portid' -o '/' -v 'service/@name' -o ' ' -b -n scan.xml`

Python parsing:
```python
import xml.etree.ElementTree as ET
tree = ET.parse('scan.xml')
for host in tree.findall('.//host'):
    addr = host.find('address').get('addr')
    for port in host.findall('.//port[state[@state="open"]]'):
        print(f"{addr}:{port.get('portid')} {port.find('service').get('name', '?')}")
```

### XML to HTML

`--webxml` — reference the Nmap.org XSL stylesheet in XML output for browser rendering.
`--stylesheet <file>` — use a custom XSL stylesheet.
Convert after the fact: `xsltproc scan.xml -o scan.html`

---

## Chaining and Routing

### Two-pass workflow (naabu → nmap)

For targets with unknown port surfaces, use `naabu` (→ `naabu.md`) for fast broad discovery, then nmap for enrichment on discovered ports:

```
naabu -host <target> -top-ports 1000 -silent -o naabu_ports.txt
# Extract port list:
ports=$(cat naabu_ports.txt | cut -d: -f2 | sort -un | paste -sd,)
# Enrich:
nmap -n -Pn -sV -sC -p "$ports" --script-timeout 30s --host-timeout 5m -oA nmap_enriched <target>
```

This is faster and more thorough than nmap's own `-p-` sweep on high-latency or filtered targets.

### nmap → httpx (HTTP service probing)

Feed nmap-discovered HTTP ports into httpx (→ `httpx.md`) for web-specific enumeration:
```
nmap -n -Pn --open -p 80,443,8080,8443,8000,3000,5000,9090 -oG - <target_range> | grep '/open' | awk '{print $2}' | httpx -silent -o live_http.txt
```

### nmap → nuclei (vulnerability scanning)

Feed nmap results into nuclei (→ `nuclei.md`) for template-based vulnerability scanning:
```
# Extract host:port from grepable:
grep 'Ports:' nmap.gnmap | awk '{print $2}' > targets.txt
nuclei -l targets.txt -as -s critical,high -rl 50 -j -o nuclei.jsonl
```

Or use XML to build protocol-qualified URLs:
```
xmlstarlet sel -t -m '//host[ports/port/state/@state="open"]' \
  -m 'ports/port[state/@state="open"][service/@name="http" or service/@name="https"]' \
  -i 'service/@name="https"' -o 'https://' -b \
  -i 'service/@name="http"' -o 'http://' -b \
  -v '../../address/@addr' -o ':' -v '@portid' -n scan.xml > urls.txt
```

### NSE results → manual follow-up

NSE script output drives targeted manual testing:
- `http-enum` results → directory/file follow-up with `feroxbuster` (→ `feroxbuster.md`) or `ffuf` (→ `ffuf.md`).
- `ssl-enum-ciphers` results → TLS assessment with `tlsx` (→ `tlsx.md`).
- `smb-enum-shares` / `smb-os-discovery` → SMB exploitation workflow.
- `vulners` CVE output → lookup in `vulnx` (→ `vulnx.md`) for exploit availability.
- `http-git` detection → `.git` dumping and source recovery.
- `dns-zone-transfer` → domain mapping with `subfinder` (→ `subfinder.md`) and `dnsx` (→ `dnsx.md`).

### Version correlation

`-sV` CPE output enables direct vulnerability lookup:
```
# From nmap XML, extract CPE strings:
xmlstarlet sel -t -m '//service/cpe' -v '.' -n scan.xml | sort -u
# Feed into vulnerability databases or nuclei tag matching.
```

Vulnerability skill routing:
- Port 80/443 open → `xss.md`, `sql_injection.md`, `csrf.md`, `ssrf.md`, `path_traversal_lfi_rfi.md`
- Port 22 open with password auth → `weak_password_detection.md`
- SMB open (445) → `smb-vuln-*` NSE scripts, then manual exploitation
- DNS (53) with zone transfer → `subdomain_takeover.md`
- SSL/TLS services → `browser_security.md` (HSTS, cert validation)

---

## Scan Validation

### Confirming port state

`--reason` reveals *why* nmap assigned a state. Confirm open ports by checking the reason:
- `syn-ack` — definitive open; the host responded with SYN/ACK to our SYN.
- `conn-refused` (via `-sT`) — definitive closed; connect() returned ECONNREFUSED.
- `no-response` — ambiguous; could be filtered or dropped. Not confirmation of either state.
- `reset` — closed (RST received).
- `host-unreach` / `net-unreach` / `admin-prohibited` — ICMP-based filtering.

### Eliminating false positives from NSE

NSE vulnerability scripts vary in reliability:
- Scripts that confirm exploitation (e.g. `ssl-heartbleed` reads back memory) are high-confidence.
- Scripts that match version strings or banners (e.g. `vulners`) report *potential* vulln based on version; these are leads, not confirmed findings.
- Scripts that check HTTP responses for patterns (e.g. `http-sql-injection`, `http-dombased-xss`) have high false-positive rates — treat as discovery, not confirmation.

Validation workflow:
1. Run vuln scripts: `nmap --script vuln -p <ports> <host>`
2. Review each finding's output for proof-of-exploitation vs. version-match.
3. Cross-reference version-match findings with `-sV` output and CVE databases (`vulnx` → `vulnx.md`).
4. Confirm exploitable findings with targeted tools: sqlmap (→ `sqlmap.md`) for SQLi, nuclei (→ `nuclei.md`) with specific CVE templates, or manual verification.

### Reproducibility

Use `-oA` and explicit flags for reproducible runs. An exact nmap command line with all flags specified (not relying on defaults) can be re-run to verify state changes after remediation.

Resume interrupted scans: `nmap --resume scan.nmap` restores from the normal-output file. Requires `-oN` or `-oA` to have been used in the original scan.

### Comparing scan results

Nmap's `ndiff` tool compares two XML scans:
`ndiff scan1.xml scan2.xml`

Shows hosts/ports that appeared, disappeared, or changed state — useful for tracking remediation or detecting service changes between assessment phases.
