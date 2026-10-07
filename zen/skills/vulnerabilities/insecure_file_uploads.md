---
name: insecure-file-uploads
description: File upload security testing covering extension bypass, content-type manipulation, and path traversal
---

# Insecure File Uploads

Upload surfaces are high risk: server-side execution (RCE), stored XSS, malware distribution, storage takeover, and DoS. Modern stacks mix direct-to-cloud uploads, background processors, and CDNs—authorization and validation must hold across every step.

## Attack Surface

- Web/mobile/API uploads, direct-to-cloud (S3/GCS/Azure) presigned flows, resumable/multipart protocols (tus, S3 MPU)
- Image/document/media pipelines (ImageMagick/GraphicsMagick, Ghostscript, ExifTool, PDF engines, office converters)
- Admin/bulk importers, archive uploads (zip/tar), report/template uploads, rich text with attachments
- Serving paths: app directly, object storage, CDN, email attachments, previews/thumbnails

## Reconnaissance

### Surface Map

- Endpoints/fields: upload, file, avatar, image, attachment, import, media, document, template
- Direct-to-cloud params: key, bucket, acl, Content-Type, Content-Disposition, x-amz-meta-*, cache-control
- Resumable APIs: create/init → upload/chunk → complete/finalize; check if metadata/headers can be altered late
- Background processors: thumbnails, PDF→image, virus scan queues; identify timing and status transitions

### Capability Probes

- Small probe files of each claimed type; diff resulting Content-Type, Content-Disposition, and X-Content-Type-Options on download
- Magic bytes vs extension: JPEG/GIF/PNG headers; mismatches reveal reliance on extension or MIME sniffing
- SVG/HTML probe: do they render inline (text/html or image/svg+xml) or download (attachment)?
- Archive probe: simple zip with nested path traversal entries and symlinks to detect extraction rules

## Detection Channels

### Server Execution

- Web shell execution (language dependent), config/handler uploads (.htaccess, .user.ini, web.config) enabling execution
- Interpreter-side template/script evaluation during conversion (ImageMagick/Ghostscript/ExifTool)

### Client Execution

- Stored XSS via SVG/HTML/JS if served inline without correct headers; PDF JavaScript; office macros in previewers

### Header and Render

- Missing X-Content-Type-Options: nosniff enabling browser sniff to script
- Content-Type reflection from upload vs server-set; Content-Disposition: inline vs attachment

### Process Side Effects

- AV/CDR race or absence; background job status allows access before scan completes; password-protected archives bypass scanning

## Core Payloads

### Web Shells and Configs

- PHP: GIF polyglot (starts with GIF89a) followed by `<?php echo 1; ?>`; place where PHP is executed
- .htaccess to map extensions to code (AddType/AddHandler); .user.ini (auto_prepend/append_file) for PHP-FPM
- ASP/JSP equivalents where supported; IIS web.config to enable script execution

**Per-server execution mapping.** Whether an uploaded file *executes* depends on
the server's handler config, not just the extension — target the specific
mapping:

| Server | Executes via | Attacker moves |
|---|---|---|
| Apache + mod_php | `AddHandler`/`SetHandler application/x-httpd-php` on an extension | alt PHP extensions `.php3 .php4 .php5 .php7 .pht .phtml .phar`; upload a `.htaccess` with `AddType application/x-httpd-php .jpg`; `MultiViews` content-negotiation to reach `shell.php` as `shell` |
| nginx + PHP-FPM | `location ~ \.php$ { fastcgi_pass ... }` + `fastcgi_split_path_info` | the path-info bug: `POST /uploads/avatar.jpg/x.php` — nginx matches `\.php$`, FPM sets `SCRIPT_FILENAME` to the `.jpg` and executes it as PHP unless `security.limit_extensions`/`cgi.fix_pathinfo=0` is set |
| IIS | handler mappings, classic ASP/ASP.NET | legacy semicolon `shell.asp;.jpg` (IIS6-era), `web.config` upload to enable execution, `.aspx`/`.ashx`/`.asmx`, 8.3 short-name tricks |
| Tomcat / Jetty | JSP servlet | upload `.jsp`/`.jspx`; if `readonly=false` on the default servlet, `PUT /shell.jsp` directly; `/manager` WAR deploy with creds |
| Node/Python/Ruby | no implicit code-by-extension | RCE comes from the *processor* (below) or from writing into a template/require path — see `path_traversal_lfi_rfi` File-Write-to-Execution |

Confirm the deployed handler config; an extension that executes on one server is
an inert file on another.

### Stored XSS

- SVG with onload/onerror handlers served as image/svg+xml or text/html
- HTML file with script when served as text/html or sniffed due to missing nosniff

### MIME Magic Polyglots

- Double extensions: avatar.jpg.php, report.pdf.html; mixed casing: .pHp, .PhAr
- Magic-byte spoofing: valid JPEG header then embedded script; verify server uses content inspection, not extensions alone
- Detector/consumer differential: make the upload validator and the later parser disagree about type, structure, or validity
- Probe detector scan windows, recursion/nesting limits, maximum bytes inspected, invalid-syntax recovery, and version-specific magic databases

### Archive Attacks

- Zip Slip: entries with `../../` to escape extraction dir; symlink-in-zip pointing outside target; nested zips
- Zip bomb: extreme compression ratios to exhaust resources in processors

### Toolchain Exploits

The upload surface is only the delivery channel; the engine downstream is where
RCE lives. The classes below name the primitive each engine class produces; the
version-boundary and GHSA metadata live in `insecure_file_uploads_novel_deep.md`
under the matching section.

- **ImageMagick — ImageTragick (CVE-2016-3714)**: delegate-coder shell-metacharacter injection in the `MVG`, `MSL`, `HTTPS`, `EPHEMERAL`, `TEXT`, `SHOW`, `WIN`, `PLT` coders — crafted image → OS command, arbitrary file read via `label:@/etc/passwd`, or SSRF via `https://`. Modern installs mitigate via `policy.xml` with `coder rights="none"`, so always inspect the deployed policy before assuming the class is closed. See `insecure_file_uploads_novel_deep.md § ImageMagick Delegate-Coder Injection — Version Boundary`.
- **Ghostscript — pipe command injection (CVE-2023-36664)**: pipe-device permission validation flaw — PS/EPS/PDF with filename beginning `%pipe%` or `|` → OS command execution on open. Reached through any upload pipeline that shells to GS (thumbnailers, PDF-to-image, ImageMagick's PS delegate). See `insecure_file_uploads_novel_deep.md § Ghostscript Pipe-Device Command Injection`.
- **Ghostscript — uniprint format-string → -dSAFER sandbox escape (CVE-2024-29510)**: attacker-controlled `upYMoveCommand` / `upWriteComponentCommands` strings reach `gs_snprintf` / `gp_fprintf` without specifier sanitization, producing `%s`/`%x` arbitrary-read and `%n` arbitrary-write primitives; a specific pointer-dereference chain flips `path_control_active` to zero, re-enabling the `%pipe%` operator for command execution. Upload-reachable in-the-wild via ImageMagick's PS delegate with EPS-disguised-as-JPG polyglots. See `insecure_file_uploads_novel_deep.md § Ghostscript uniprint Format-String Sandbox Escape`.
- **Ghostscript — -dSAFER restoration-of-privilege class (CVE-2018-16509 and successors)**: legacy sandbox-escape pattern — permission state restored after a privileged op completes without re-validating the newly accessible resource. GS RCE has recurred across releases, so version-match the specific bypass; see `insecure_file_uploads_novel_deep.md § Ghostscript -dSAFER Historical Catalog`.
- **ExifTool** metadata parsing bugs — overly large or crafted EXIF/IPTC/XMP fields reach eval sinks in the DjVu-annotation class, which historically reached RCE; see `insecure_file_uploads_novel_deep.md § ExifTool DjVu Eval Historical Class`.

Separate from engine-class RCE, two upload-primitive classes drive straight to webroot write without a conversion engine in the loop:

- **Apache Struts — multipart mass-assignment to webroot path (CVE-2024-53677, S2-067)**: a multipart POST includes a legitimate `file` field plus a crafted `top.fileFileName` parameter containing path-traversal sequences, which the ParametersInterceptor assigns onto the action class's field via OGNL value-stack access, writing (e.g.) a JSP shell to `../usr/local/tomcat/webapps/ROOT/shell.jsp`. Primitive-only; no undocumented-keyword or version-range claims. See `insecure_file_uploads_novel_deep.md § Struts top.fileFileName Mass-Assignment Primitive`.
- **SharePoint — ToolShell unauth file-drop (CVE-2025-53770, "ToolShell")**: single unauthenticated POST to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` with a spoofed `Referer: /_layouts/15/signout.aspx` writes an `.aspx` file to the SharePoint webroot (observed artifact: `spinstall0.aspx`). The *delivery/activation* primitive is the file-upload class; the full-RCE chain requires the dropped shell to leak the ASP.NET MachineKey and forge `__VIEWSTATE` via `ysoserial.net`, which routes to `insecure_deserialization.md`. See `insecure_file_uploads_novel_deep.md § SharePoint ToolShell Delivery Primitive`.

### SVG → XXE

An SVG is XML, so a **server-side** SVG consumer that parses it with an
XXE-capable XML parser (rsvg, ImageMagick's MSVG/SVG delegate, resvg, a
headless-browser rasterizer, or an "SVG sanitizer" that first parses the DOM) is
an XXE sink even when the browser-XSS path is blocked:
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="0" y="20">&xxe;</text></svg>
```
The file content lands in the rendered PNG/PDF (or an error). Load `xxe` for the
parser-defaults matrix and OOB/local-DTD exfiltration; upload is just the
delivery channel.

### Upload → LFI / Filter-Chain

When the app also has a file-inclusion sink, upload becomes RCE even if the
upload location isn't web-executable: drop a payload (a GIF/JPEG-polyglot PHP,
or any file whose bytes you control), then have the LFI `include` it by its
stored path. On PHP, you often don't even need the upload to be valid — the
`php://filter` convert-chain turns a plain LFI into RCE with no writable file at
all. Trace the upload's *stored path* (predictable key, returned URL, temp name)
and hand it to the inclusion sink. Load `path_traversal_lfi_rfi` for the
filter-chain generator and the File-Write-to-Execution resolver analysis.

### Cloud Storage Vectors

- S3/GCS presigned uploads: attacker controls `Content-Type`/`Content-Disposition`; set `text/html` or `image/svg+xml` and inline rendering follows if the server does not constrain the signed fields. The signing-time policy is the gate — a POST policy with no `conditions` clause on `Content-Type` or an unconstrained prefix on `key` lets the attacker upload HTML under a path the app later serves inline.
- Signed-URL replay: a presigned URL re-used after the uploaded blob was overwritten (e.g. the attacker races to update the object between signing and consuming) delivers attacker content under a URL the app has already committed to in its database. Confirm by checking whether presigned URLs are issued once per transaction or recycled across sessions.
- Signed-field tampering with S3 POST policy: `signature` + `policy` cover `conditions`, but the attacker-provided *additional* fields (not listed in the policy's `conditions`) are accepted by S3 anyway. If the server-side policy omits `starts-with` on `$Content-Type`, the attacker sets any Content-Type; if it omits a condition on `$key`, the attacker writes to arbitrary paths within the bucket.
- Public-read ACL or permissive bucket policies expose uploads broadly; combined with no `X-Content-Type-Options: nosniff` and inline Content-Disposition, this is stored XSS with the bucket's domain as the origin.
- Object key injection via user-controlled path prefixes: a sign request where the client supplies `key=user-123/avatar.jpg` and the server fails to constrain the prefix lets the attacker write `key=admin/htaccess` or `key=public/shell.jsp` to a path the app serves executably.
- Pre-signed GET replay for exfiltration: a signed GET URL for a different user's object leaks when key enumeration is predictable; route to `idor.md` for the authorization-side analysis.

## Advanced Techniques

### Resumable Multipart

- Change metadata between init and complete (e.g., swap Content-Type/Disposition at finalize) — many servers validate on init but trust client-supplied metadata on complete
- Upload benign chunks, then swap last chunk or complete with different source — content-type sniffing commonly reads only the first chunk, so a benign JPEG header followed by a late malicious chunk defeats early scanners
- S3 multipart upload (MPU) composition: `CompleteMultipartUpload` concatenates parts without re-scanning; parts can be uploaded from different sources with independently valid magic-byte headers (polyglot assembly at the storage layer)
- tus protocol `Upload-Offset` and `Upload-Length` header manipulation: a resumable upload that validates total length against policy at init but accepts a different final length on `PATCH` with the `Upload-Concat` extension can smuggle larger files than the policy allows

### Filename and Path

- Unicode homoglyphs, trailing dots/spaces, device names, reserved characters to bypass validators
- Null-byte truncation on legacy stacks; overlong paths; case-insensitive collisions overwriting existing files

### Processing Races

- Request file immediately after upload but before AV/CDR completes
- Trigger heavy conversions (large images, deep PDFs) to widen race windows

### Metadata Abuse

- Oversized EXIF/XMP/IPTC blocks to trigger parser flaws
- Payloads in document properties of Office/PDF rendered by previewers

### Header Manipulation

- Force inline rendering with Content-Type + inline Content-Disposition
- Cache poisoning via CDN with keys missing Vary on Content-Type/Disposition

## Bypass Techniques

### Validation Gaps

- Client-side only checks; relying on JS/MIME provided by browser
- Trusting multipart boundary part headers blindly
- Extension allowlists without server-side content inspection
- One parser validates metadata or leading bytes while another parser processes the full file
- Type-detection wrappers assumed identical even when they bundle different library/database versions

### Evasion Tricks

- Double extensions, mixed case, hidden dotfiles, extra dots (file..png), long paths with allowed suffix
- Multipart name vs filename vs path discrepancies; duplicate parameters and late parameter precedence

## Special Contexts

### Rich Text Editors

- RTEs allow image/attachment uploads and embed links; verify sanitization and serving headers

### Mobile Clients

- Mobile SDKs may send nonstandard MIME or metadata; servers sometimes trust client-side transformations

### Serverless and CDN

- Direct-to-bucket uploads with Lambda/Workers post-processing; verify security decisions are not delegated to frontends
- CDN caching of uploaded content; ensure correct cache keys and headers

## Testing Methodology

1. **Map the pipeline** - Client → ingress → storage → processors → serving. Note where validation and auth occur
2. **Identify allowed types** - Size limits, filename rules, storage keys, and who serves the content
3. **Collect baselines** - Capture resulting URLs and headers for legitimate uploads
4. **Map validators and consumers** - Identify the detector/library/version when possible and every later parser, converter, renderer, or browser context
5. **Exercise bypass families** - Extension games, MIME/content-type, magic bytes, parser limits, polyglots, metadata payloads, archive structure
6. **Validate execution** - Prove the accepted object reaches a more privileged consumer and can execute or render active content

## Validation

1. Demonstrate execution or rendering of active content: web shell reachable, or SVG/HTML executing JS when viewed
2. Show filter bypass: upload accepted despite restrictions with evidence on retrieval
3. Prove header weaknesses: inline rendering without nosniff or missing attachment
4. Show race or pipeline gap: access before AV/CDR; extraction outside intended directory
5. Provide reproducible steps: request/response for upload and subsequent access

## False Positives

- Upload stored but never served back; or always served as attachment with strict nosniff
- Converters run in locked-down sandboxes with no external IO and no script engines
- AV/CDR blocks the payload and quarantines; access before scan is impossible by design

## Impact

- Remote code execution on application stack or media toolchain host
- Persistent cross-site scripting and session/token exfiltration via served uploads
- Malware distribution via public storage/CDN; brand/reputation damage
- Data loss or corruption via overwrite/zip slip; service degradation via zip bombs

## Pro Tips

1. Keep PoCs minimal: tiny SVG/HTML for XSS, a single-line PHP/ASP where relevant
2. Always capture download response headers and final MIME; that decides browser behavior
3. Prefer transforming risky formats to safe renderings (SVG→PNG) rather than complex sanitization
4. In presigned flows, constrain all headers and object keys server-side
5. For archives, extract in a chroot/jail with explicit allowlist; drop symlinks and reject traversal
6. Test finalize/complete steps in resumable flows; many validations only run on init
7. Verify background processors with EICAR and tiny polyglots
8. When you cannot get execution, aim for stored XSS or header-driven script execution
9. Validate that CDNs honor attachment/nosniff
10. Document full pipeline behavior per asset type
11. Reproduce detector/consumer mismatches on the deployed library versions; OS packages and language bindings may ship different limits

## Summary

Secure uploads are a pipeline property. Enforce strict type, size, and header controls; transform or strip active content; never execute or inline-render untrusted uploads; and keep storage private with controlled, signed access.
