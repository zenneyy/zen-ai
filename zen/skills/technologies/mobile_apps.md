---
name: mobile-apps
description: Test the API backend and web-detectable surfaces of iOS and Android mobile applications; covers cert-pinning bypass for API exposure, deeplink abuse, WebView misconfiguration, exported component exploitation, and hardcoded secret extraction chained to backend API testing
---

# Mobile Applications

This skill frames mobile application security around the backend API the app communicates with — the scanner is web/API-centric and tests HTTP surfaces, not static binaries. The mobile app is relevant as the client that exposes the API surface (via cert-pinning bypass), leaks secrets that unlock API access (hardcoded keys), and introduces client-side trust assumptions the API may rely on (deeplinks, WebView bridges, exported components). For API authorization flaws reached via mobile, see `idor` and `broken_function_level_authorization`. For token/JWT handling, see `authentication_jwt` (which has a dedicated `### Mobile` section). For OAuth deeplink flows, see `protocols/oauth`. For hardcoded secrets and credential exposure, see `cryptographic_failures` and `information_disclosure`. For Firebase-specific backend misconfig, see `firebase`.

## Reconnaissance and Detection

The primary web-detectable signals for a mobile app's presence come from app-association files the domain must serve publicly:

```
# iOS — Apple App Site Association (AASA)
curl -s https://<target>/.well-known/apple-app-site-association | jq .
# Returns: applinks.details[].appIDs (TEAMID.bundle.id), URL path patterns the app handles

# Android — Digital Asset Links
curl -s https://<target>/.well-known/assetlinks.json | jq .
# Returns: target.package_name, target.sha256_cert_fingerprints
```

Both files are required by design — devices fetch them to verify deeplink ownership. They reveal the app's identity (bundle ID, package name), associated URL paths (endpoint wordlist material for the scanner), signing certificate fingerprints, and the development team identity. Parse `applinks.details[].components[].path` patterns from AASA to discover app-handled URL paths that may have different backend authorization than browser-accessed paths.

**Secondary signals** (backend-side):
- Mobile user-agents hitting the API (`okhttp/`, `Alamofire/`, `Dart/`, `CFNetwork/`, custom app UA strings)
- App-specific API endpoints (`/api/mobile/`, `/api/v1/app/`, versioned mobile-only routes)
- Push notification registration endpoints, device-token submission paths
- App-specific authentication flows (device attestation, biometric-gated token exchange)

## Key Vulnerabilities

### Cert-Pinning Bypass — Exposing the API Surface

Cert-pinning bypass is the prerequisite, not the finding. Bypassing pinning exposes the app's API traffic to a proxy so the scanner's web-vuln specialists can test the backend.

```
# Objection (Frida-based, one-command bypass for standard pinning)
objection -g com.target.app explore -s "android sslpinning disable"
objection -g com.target.app explore -s "ios sslpinning disable"

# Frida script for custom implementations (OkHttp CertificatePinner, TrustKit, etc.)
frida -U -f com.target.app -l frida-multiple-unpinning.js --no-pause
```

Requires a rooted/jailbroken device or emulator with Frida server running. Once bypassed, route traffic through mitmproxy or Burp and feed the discovered API endpoints to the scanner.

### Deeplink and Custom URL Scheme Abuse

Custom URL schemes (`myapp://`) have no ownership verification — any app on the device can register the same scheme and intercept links. The highest-impact attack is OAuth callback hijacking: an authorization code redirected to a malicious app claiming the scheme is exchanged for tokens against the backend.

- **OAuth callback hijack:** the authorization code grant uses `myapp://callback?code=<code>` as `redirect_uri`; a competing app intercepts the code and exchanges it. RFC 8252 documents this as a known threat for native OAuth.
- **Parameter injection:** deeplinks passing parameters directly into backend API calls without server-side re-validation.
- **Android intent abuse:** `intent://` URIs specify target components, extras, and flags — a web page can craft intents that trigger unintended app actions chaining to backend calls.

iOS Universal Links and Android App Links mitigate hijacking via HTTPS-verified `.well-known` association files, but misconfiguration is common — overly broad path patterns, missing verification files, or fallback to unverified custom schemes.

### WebView Misconfiguration

Android `addJavascriptInterface` (pre-API 17) allowed full Java reflection from JavaScript — the defining WebView vulnerability class. Post-API 17, only `@JavascriptInterface`-annotated methods are callable, but any page loaded in that WebView can invoke them without origin restriction.

- `setAllowFileAccess(true)` / `setAllowUniversalAccessFromFileURLs(true)` — JavaScript in the WebView reads local files and exfiltrates via network requests.
- JavaScript enabled on WebViews loading untrusted external URLs — standard XSS class (see `xss`) but with access to the native bridge.
- iOS `WKWebView` `WKScriptMessageHandler` bridge has no built-in origin check — developers must validate `WKScriptMessage.frameInfo.securityOrigin` manually. Missing validation exposes bridge functions to any page the WebView loads.

### Insecure Local Storage

Tokens and secrets stored in plaintext on-device can be extracted and replayed against the API:

- **Android:** `SharedPreferences` (plaintext XML in `/data/data/<pkg>/shared_prefs/`), unencrypted SQLite databases, external storage. Expected control: `EncryptedSharedPreferences`, Android Keystore.
- **iOS:** `NSUserDefaults`/plist files (plaintext), Keychain with wrong protection class (`kSecAttrAccessibleAlways` instead of `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`), unencrypted Core Data/SQLite.

The scanner-relevant angle: extracted long-lived tokens or API keys are replayed against backend endpoints.

### Exported Android Components

Exported activities, services, content providers, and broadcast receivers (CWE-926) are invocable by any app on the device. Content providers without permission enforcement expose queries over app data. Activities launched with crafted intents can bypass authentication screens or trigger privileged backend operations. The scanner-relevant chain: exported components often trigger backend API calls with attacker-controlled parameters via intent extras.

### Hardcoded Secrets in App Bundles

API keys, Firebase credentials, AWS access keys, and third-party service tokens embedded in APK/IPA bundles. Extractable via `apktool`/`jadx` (Android) or class-dump/decrypted IPA inspection (iOS). Common locations: `google-services.json` / `GoogleService-Info.plist`, `strings.xml`, `BuildConfig` fields, `Info.plist`, hardcoded in source. The scanner-relevant impact: extracted keys are tested directly against the backend API.

## Testing Methodology

1. **Web detection** — fetch `/.well-known/apple-app-site-association` and `/.well-known/assetlinks.json`; parse app identifiers and associated URL paths; add discovered paths to the scanner's endpoint wordlist.
2. **API surface extraction** — bypass cert-pinning, proxy app traffic, catalog all API endpoints the app calls; compare with endpoints discovered via web reconnaissance for mobile-only routes.
3. **Deeplink audit** — extract registered URL schemes from `AndroidManifest.xml` / `Info.plist`; test OAuth callback URIs for scheme-hijack susceptibility; probe deeplink parameters for backend-side injection.
4. **WebView review** — identify WebViews loading external content with JavaScript bridges; test bridge function invocation from untrusted origins.
5. **Secret extraction** — decompile the bundle; grep for API keys, tokens, and credentials; test each against the backend.
6. **API authz differential** — compare authorization enforcement on mobile-only endpoints vs web endpoints; mobile routes often skip web-added middleware (see `broken_function_level_authorization`).

## Validation

1. Show the `.well-known` association files and the app identifiers they reveal.
2. API interception: show proxied API traffic after cert-pinning bypass with the endpoint list.
3. Deeplink abuse: show the crafted deeplink and the backend action or token it produces.
4. Secret extraction: show the extracted key/token and the API response when it is used directly.
5. Authz differential: show a mobile-only endpoint accepting a request that the web client's equivalent rejects.

## False Positives

- `.well-known` association files are publicly required by design — their presence is expected, not a finding. The finding is overly broad path patterns or missing verification entries.
- Firebase API keys in the bundle are semi-public by design (they identify the project, not authenticate) — the finding is when Firebase Security Rules allow unauthenticated access (see `firebase`).
- Cert-pinning absence on development/staging builds is expected — confirm the build is production.
- Custom URL schemes without App Link verification are only exploitable if the scheme carries sensitive parameters (OAuth codes, session tokens).
- An exported component that requires a signature-level permission is not exploitable by a third-party app.

## Pro Tips

1. Start with the `.well-known` files — they are free intelligence: app identity, URL paths, and team/signing info, all from a standard web request.
2. Mobile-only API routes are the highest-yield scanner target — they frequently lack authorization middleware that the web client's routes enforce.
3. Compare mobile vs web OAuth flows — mobile often uses PKCE but web may not, or vice versa; the weaker flow is the finding.
4. `google-services.json` leaks the Firebase project ID, API key, and storage bucket — feed these to `firebase` skill checks even if Firebase is not obviously in scope.
5. Pair with `protocols/oauth` for OAuth-in-mobile flows, `authentication_jwt` for token handling, and `csrf` for deeplink/WebView cookie-sending edge cases.

## Summary

Mobile app security testing through this scanner focuses on the backend API the app communicates with. The `.well-known` app-association files are the primary web-detectable signal. Cert-pinning bypass exposes the API surface for scanner analysis. The highest-value findings are mobile-only API routes with weaker authorization than their web equivalents, OAuth callback scheme hijacking, WebView bridge abuse chaining to backend operations, and hardcoded secrets that unlock direct API access. This is a design/misconfiguration surface — findings center on how the mobile client weakens the backend's security assumptions.
