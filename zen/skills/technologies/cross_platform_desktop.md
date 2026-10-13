---
name: cross-platform-desktop
description: Test cross-platform desktop and mobile applications built with Tauri, Flutter, or React Native; covers IPC/bridge security, capability/scope bypass CVE classes, insecure OTA update channels, and framework-specific secret exposure
---

# Cross-Platform Desktop & Mobile Frameworks

This skill covers Tauri, Flutter, and React Native — the three web-to-native frameworks that `electron_desktop_apps` explicitly disclaims (line 8: "do not apply Electron-specific conclusions to NW.js, CEF, Tauri, or Wails"). Each framework has distinct IPC/bridge, sandbox, update, and process APIs that differ fundamentally from Electron's renderer→preload→IPC→main model. For Electron, see `electron_desktop_apps`. For API authorization flaws the app's backend exposes, see `idor` and `broken_function_level_authorization`. For mobile-specific deeplink and `.well-known` detection surfaces on iOS/Android, see `mobile_apps`. For hardcoded secrets, see `cryptographic_failures` and `information_disclosure`.

## Reconnaissance and Detection

Detection from the web/API vantage point is limited — these are client-side applications. The strongest signals are indirect:

**Tauri** — `Content-Security-Policy` headers referencing `tauri://localhost` or `https://tauri.localhost`; update manifest endpoints (JSON with `version`, `url`, `signature` fields in Tauri updater format); `__TAURI__` or `__TAURI_INTERNALS__` in served JavaScript when `withGlobalTauri` is enabled; `tauri://` in deeplink or `.well-known/assetlinks.json` registration.

**Flutter** — `flutter_service_worker.js` and `flutter.js` in web builds; `main.dart.js` or `main.dart.wasm` in served assets; `libflutter.so` (Android) / `Flutter.framework` (iOS) in the app bundle; `flutter_assets/` directory containing Dart AOT snapshots.

**React Native** — `index.android.bundle` / `main.jsbundle` in the app package (full JS source or Hermes bytecode with `.hbc` magic bytes); `com.facebook.react` package references in `AndroidManifest.xml`; Metro bundler dev-server on staging builds (`/status` returning `packager-status:running`).

## Tauri

Tauri applications run a Rust backend with a webview frontend (WebKitGTK on Linux, WebView2 on Windows, WKWebView on macOS). The IPC boundary is between JavaScript in the webview and Rust `#[tauri::command]` handlers.

### IPC and Capability Surface

**Tauri v1** used a command allowlist in `tauri.conf.json` — a flat allow/deny list controlling which Tauri APIs the frontend could invoke. **CVE-2022-46171** (CVSS 6.8) demonstrated that filesystem glob patterns (`*`, `?`, `[...]`) in scope definitions matched more paths than intended, exposing sub-folder content beyond allowed scopes.

**Tauri v2** replaced the allowlist with a capability-based permission system: per-window permission grants scoped by window label. Each command requires an explicit capability grant — a missing grant denies the call. Test whether capabilities are scoped per-window or granted globally (a single default capability granting broad permissions to all windows is over-scoped).

`withGlobalTauri: true` in build config exposes the `__TAURI__` IPC bridge to all loaded content, including remote pages and XSS payloads. Any script in the page can invoke any IPC command the window's capability permits.

### IPC Isolation Bypass

Tauri has a recurring CVE class of IPC isolation failures:

- **CVE-2024-35222** (CVSS 5.9) — remote-origin iframes bypass origin checks, reaching IPC endpoints without explicit capability/allowlist authorization. An attacker-controlled iframe can invoke valid commands with unwanted consequences.
- **CVE-2023-31134** (CVSS 4.8) — redirecting an existing Tauri window to an external website bypasses IPC isolation, granting the external site access to the window's IPC commands.

The pattern: any mechanism that loads untrusted content into a context with IPC access (iframes, redirects, navigation) must be tested — the isolation has failed repeatedly.

### Filesystem Scope Bypass

**CVE-2022-39215** (CVSS 8.3) — `readDir` called recursively followed symlinks or junction points outside the defined `fs` scope, exposing arbitrary filesystem content. Custom Rust commands implementing their own file operations may reintroduce the same class if they skip canonicalization.

### Update Channel Security

**CVE-2023-46115** (CVSS 8.4) — the Tauri updater's private key and passphrase could leak into the bundled application through build configuration (environment variables embedded at compile time). An attacker extracting the key from the binary can sign malicious updates. The updater uses Ed25519 signatures — verify that the signing key is not present in the distributed binary and that the update manifest URL enforces TLS with no redirect to attacker-controlled hosts.

## Flutter

Flutter compiles Dart to native ARM code (mobile) or JavaScript/Wasm (web). The security-relevant boundary is the platform channel between Dart and native code.

### Platform Channel Exposure

`MethodChannel` and `EventChannel` connect Dart to native Android/iOS code. There is no channel-level sandboxing — any Dart code can invoke any registered channel method. The finding is when a channel handler performs privileged operations (file access, credential retrieval, system commands) without validating the call context or arguments.

### Bundle Inspection

- **Debug builds:** Dart source is recoverable via `strings` on snapshot files.
- **Release builds:** Dart AOT snapshots (`isolate_snapshot_data`, `vm_snapshot_data`) are reversible with `darter`, `Doldrums`, or `reFlutter` — class names, method names, and string constants are recoverable. Embedded API keys, endpoints, and configuration values are extractable.
- **Web builds:** `main.dart.js` is unobfuscated unless `--obfuscate` with `--split-debug-info` is explicitly enabled. Rarely used.

### Secret Exposure

`flutter_dotenv` and hardcoded values in Dart source are bundled into the app package. The `flutter_secure_storage` plugin uses Keychain (iOS) / EncryptedSharedPreferences (Android) — verify it is actually used for sensitive values rather than `shared_preferences` (plaintext). Secrets in AOT snapshots survive compilation and are extractable via string analysis.

Flutter has no framework-level CVEs — security findings center on platform channel validation, plugin behavior, and secret storage patterns. This is a design-class surface.

## React Native

React Native bridges JavaScript (JavaScriptCore or Hermes runtime) to native modules. The JS bundle is the primary attack surface for static analysis.

### JS Bridge and Bundle Inspection

- **Plain JS bundle:** `index.android.bundle` / `main.jsbundle` contains the full application source — API endpoints, business logic, hardcoded secrets, and route definitions are directly readable.
- **Hermes bytecode:** `.hbc` files are decompilable with `hbcdump` (Hermes CLI) or `hermes-dec` — class/function structure, string constants, and API URLs are recoverable from bytecode.
- **Native modules:** Custom modules registered via `ReactPackage` (Android) / `RCTBridgeModule` (iOS) expose native functions to the JS context. Over-exposed native modules (file system access, shell execution, keychain operations) without argument validation are the finding.

### Secret Exposure

`react-native-config` writes environment variables into the bundle at build time — they are plaintext in the binary, not secrets. `AsyncStorage` (plaintext SQLite) is frequently misused for tokens instead of `react-native-keychain` (OS credential store). Hermes bytecode string tables retain API keys and endpoint URLs despite compilation.

### Deeplink Handling

React Native's `Linking` API registers URL schemes via `AndroidManifest.xml` intent-filters and iOS URL types. The same custom-scheme hijack class as native mobile applies (see `mobile_apps`). React Navigation's deep linking maps URL patterns to screens — overly broad patterns (`*` path segments) may route attacker-controlled parameters to sensitive screens.

React Native has no framework-level CVEs affecting production apps — security findings are design-class: JS bridge exposure, deeplink parameter injection, and secret extraction.

## Insecure Over-the-Air Updates

- **CodePush (React Native):** Pushes JS bundles that replace the app's code without an app store update. If bundle signing is not enforced, an attacker controlling the update channel injects arbitrary JavaScript. Microsoft AppCenter (original CodePush host) was retired March 2025 — verify the successor endpoint enforces signature verification.
- **Tauri updater:** Ed25519 signatures are mandatory, but CVE-2023-46115 showed the signing key could leak into the binary. Verify the update manifest URL, TLS enforcement, and key absence in the distributed build.
- **Flutter (Shorebird):** Dart code-push solutions are emerging. Patch signing is available but opt-in — verify it is enabled and the update endpoint is authenticated.

The update channel is an executable supply chain — treat the update manifest URL, signature verification, and key management as a single trust boundary (same class as `electron_desktop_apps` § Updates and Native Extensions).

## Testing Methodology

1. **Identify framework** — check for Tauri/Flutter/RN signatures in the app bundle, served assets, or `.well-known` files.
2. **Bundle extraction** — extract and decompile: Tauri (resource directory), Flutter (AOT snapshot analysis), RN (JS bundle or Hermes bytecode decompilation).
3. **IPC/bridge audit** — enumerate exposed commands (Tauri capabilities), platform channels (Flutter), native modules (RN); test each for argument validation and scope.
4. **Secret extraction** — grep decompiled source for API keys, tokens, endpoints; test extracted credentials against the backend.
5. **Update channel** — locate the update manifest URL; verify signature enforcement; check for key leakage in the binary.
6. **Scope/permission testing (Tauri)** — attempt filesystem, shell, and network operations beyond declared capabilities; test glob/symlink scope bypass variants.

## Validation

1. Show the framework identification evidence (bundle signatures, served assets).
2. IPC abuse: show the command/channel invocation and the privileged operation it triggers with attacker-controlled input.
3. Scope bypass (Tauri): show the capability configuration and the out-of-scope resource accessed.
4. Secret extraction: show the extracted credential and the API response when used directly.
5. Update channel: show the update manifest, signature verification status, and (if applicable) the leaked signing key location in the binary.

## False Positives

- `withGlobalTauri` enabled in development builds is expected — confirm the production build.
- Flutter debug builds with readable Dart source are not production artifacts — verify the build mode.
- RN Metro bundler dev-server exposure on localhost during development is expected — the finding is when it is reachable on a non-loopback interface in staging/production.
- Tauri filesystem scope allowing access to the app's own data directory is by design — the finding is scope extending beyond the app's data.
- CodePush or OTA update presence is not a finding — the finding is missing signature verification or leaked signing keys.

## Pro Tips

1. Tauri v2 capabilities are the ACL — enumerate them first (`src-tauri/capabilities/`); a single default capability granting broad permissions to all windows is the finding.
2. React Native JS bundles are the fastest path to endpoint discovery — grep for `https://`, `api/`, `Bearer`, `Authorization` across the extracted bundle.
3. Flutter's `--obfuscate` flag is rarely used — most release builds retain class and method names in the AOT snapshot.
4. Cross-reference extracted API endpoints with `idor` and `broken_function_level_authorization` — framework-specific clients often hit backend routes the web client does not.
5. The update manifest URL is a high-value MITM target — verify HTTPS enforcement and certificate validation on the update check, not just the download.
6. Delineate from `electron_desktop_apps`: Electron's preload/contextBridge/IPC model does not apply to Tauri (Rust commands), Flutter (platform channels), or RN (native modules).

## Summary

Tauri, Flutter, and React Native each implement a distinct web-to-native bridge with different trust boundaries than Electron. Tauri's security depends on capability scoping and Rust command validation — its CVE history (CVE-2022-46171, CVE-2022-39215, CVE-2024-35222, CVE-2023-46115) centers on scope bypass and IPC isolation failure. Flutter and React Native are design-class surfaces: platform channel / native module exposure, bundle-extractable secrets, and OTA update integrity are the findings. For all three, the decompiled client bundle is the primary source of backend API endpoint discovery and secret extraction.
