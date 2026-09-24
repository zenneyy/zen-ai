---
name: subdomain-takeover
description: Subdomain takeover testing for dangling DNS records and unclaimed cloud resources
---

# Subdomain Takeover

Subdomain takeover lets an attacker serve content from a trusted subdomain by claiming resources referenced by dangling DNS (CNAME/A/ALIAS/NS) or mis-bound provider configurations. Consequences include phishing on a trusted origin, cookie and CORS pivot, OAuth redirect abuse, and CDN cache poisoning.

Use `infrastructure_lifecycle` instead for expired registrable domains, MX/recovery identity, update/control endpoints, or long-lived software consumers. Provider error fingerprints are leads; confirm current claimability and custom-domain ownership requirements from authoritative provider behavior/documentation.

## Attack Surface

- Dangling CNAME/A/ALIAS to third-party services (hosting, storage, serverless, CDN)
- Orphaned NS delegations (child zones with abandoned/expired nameservers)
- Decommissioned SaaS integrations (support, docs, marketing, forms) referenced via CNAME
- CDN "alternate domain" mappings (CloudFront/Fastly/Azure CDN) lacking ownership verification
- Storage and static hosting endpoints (S3/Blob/GCS buckets, GitHub/GitLab Pages)

## Reconnaissance

### Enumeration Pipeline

- Subdomain inventory: combine CT (crt.sh APIs), passive DNS sources, in-house asset lists, IaC/terraform outputs
- Resolver sweep: use IPv4/IPv6-aware resolvers; track NXDOMAIN vs SERVFAIL vs provider-branded 4xx/5xx
- Record graph: build a CNAME graph and collapse chains to identify external endpoints

```bash
# enumerate -> resolve CNAME chains -> keep only names that dangle (NXDOMAIN
# at the final target or resolving into a provider range) -> fingerprint
subfinder -d example.com -all -silent -o subs.txt
dnsx -l subs.txt -cname -resp -silent -o cname.txt          # subdomain [CNAME target]
# dangling = CNAME target itself NXDOMAINs (nothing owns the pointed-at name)
awk '{print $2}' cname.txt | sed 's/[][]//g' | dnsx -silent -rcode nxdomain -o dangling-targets.txt
httpx -l subs.txt -sc -title -cname -web-server -silent -o probe.txt
# targeted takeover fingerprints
nuclei -l subs.txt -t http/takeovers/ -silent -o takeover-hits.txt
```

### DNS Indicators

- CNAME targets ending in provider domains: `github.io`, `amazonaws.com`, `cloudfront.net`, `azurewebsites.net`, `blob.core.windows.net`, `fastly.net`, `vercel.app`, `netlify.app`, `herokudns.com`, `trafficmanager.net`, `azureedge.net`, `akamaized.net`, `ghost.io`, `surge.sh`, `pantheonsite.io`, `bitbucket.io`, `wordpress.com`, `ngrok.io`, `readthedocs.io`, `statuspage.io`, `wixdns.net`, `myshopify.com`, `zendesk.com`, `uservoice.com`, `helpscoutdocs.com`, `readme.io` — see the HTTP Fingerprints corpus table below for the full set with per-provider status
- Orphaned NS: subzone delegated to nameservers on a domain that has expired or no longer hosts authoritative servers
- MX to third-party mail providers with decommissioned domains
- TXT/verification artifacts (`asuid`, `_dnsauth`, `_github-pages-challenge`) suggesting previous external bindings

### HTTP Fingerprints

The unclaimed-resource body is a *lead*, not a verdict — the status column
tracks the community consensus (EdOverflow's `can-i-take-over-xyz`), which
itself lags provider changes, so confirm current claimability against live
provider behavior before rating (see Severity). Status legend: **V** =
generally claimable, **E** = edge case (claimable only under specific
conditions, e.g. the resource was deleted but the name is re-registerable),
**N** = provider enforces ownership (the fingerprint is a serving miss, not
a takeover).

| Provider | CNAME / target | Fingerprint | Status |
|---|---|---|---|
| AWS S3 | `*.s3.amazonaws.com`, `*.s3-website-<region>.amazonaws.com` | `The specified bucket does not exist` / `NoSuchBucket` | V |
| CloudFront | `*.cloudfront.net` | `The request could not be satisfied` (serving miss); claim blocked with `CNAMEAlreadyExists` / `ViewerCertificateException` | N |
| Azure App Service | `*.azurewebsites.net` | `NXDOMAIN` after resource delete | V |
| Azure Traffic Manager | `*.trafficmanager.net` | `NXDOMAIN` | V |
| Azure Cloud Service | `*.cloudapp.net`, `*.cloudapp.azure.com` | `NXDOMAIN` | V |
| Azure Blob | `*.blob.core.windows.net` | `NXDOMAIN` | V |
| Azure CDN | `*.azureedge.net` | `NXDOMAIN` | V |
| Fastly | `*.fastly.net` | `Fastly error: unknown domain:` | N (TLS/domain verification) |
| GitHub Pages | `*.github.io` | `There isn't a GitHub Pages site here.` | E |
| Heroku | `*.herokuapp.com`, `*.herokudns.com` | `No such app` / `There's nothing here, yet.` | E |
| Netlify | `*.netlify.app` | `Not Found - Request ID:` | E |
| Vercel | `cname.vercel-dns.com`, `*.vercel.app` | `DEPLOYMENT_NOT_FOUND` | E |
| Shopify | `*.myshopify.com` | `Sorry, this shop is currently unavailable.` | E (custom-domain verification) |
| Zendesk | `*.zendesk.com` | `Help Center Closed` | N |
| Ghost | `*.ghost.io` | `Site unavailable` / `Failed to resolve DNS path for this host` | V |
| Readme.io | `*.readme.io` | `The creators of this project are still working on making everything perfect!` | V |
| Surge.sh | CNAME `*.surge.sh` or A `45.55.110.124` | `project not found` | V |
| Pantheon | `*.pantheonsite.io` | `404 error unknown site!` | V |
| Bitbucket | `*.bitbucket.io` | `Repository not found` | V |
| WordPress.com | `*.wordpress.com` | `Do you want to register *.wordpress.com?` | V |
| Cargo Collective | provider A/CNAME | `404 Not Found` (Cargo template) | V |
| Tumblr | `domains.tumblr.com` | `Whatever you were looking for doesn't currently exist at this address` | E |
| Tilda | A `178.248.237.68` | `Please renew your subscription` | E |
| Webflow | `proxy-ssl.webflow.com` | `The page you are looking for doesn't exist or has been moved.` | E |
| Wix | `*.wixdns.net` | `Looks Like This Domain Isn't Connected To A Website Yet!` | E |
| Intercom | `custom.intercom.help` | `Uh oh. That page doesn't exist.` | E |
| Smartling | provider CNAME | `Domain is not configured` | E |
| Statuspage | `*.statuspage.io` | provider-branded 404 | N (DNS verification) |
| HubSpot | `*.hs-sites.com` | `This page isn't available` | N |
| Unbounce | `unbouncepages.com` | `The requested URL was not found on this server.` | N |
| UserVoice | `*.uservoice.com` | `This UserVoice subdomain is currently available!` | N |
| Desk | `*.desk.com` | `Please try again or try Desk.com free for 14 days.` | N |
| Kinsta | provider CNAME | `No Site For Domain` | N |
| Help Scout | `*.helpscoutdocs.com` | `No settings were found for this company:` | V |
| Help Juice | `*.helpjuice.com` | `We could not find what you're looking for.` | V |
| Campaign Monitor | `*.createsend.com` | `Trying to access your account?` | V |
| Canny | `*.canny.io` | `Company Not Found` | V |
| Agile CRM | provider CNAME | `Sorry, this page is no longer available.` | V |
| GetResponse | provider A record | `With GetResponse Landing Pages, lead generation has never been easier` | V |
| HatenaBlog | `hatenablog.com` | `404 Blog is not found` | V |
| Gemfury | provider CNAME | `404: This page could not be found.` | V |
| LaunchRock | provider CNAME | `HTTP_STATUS=500` server error | V |
| Ngrok | `*.ngrok.io` | `Tunnel *.ngrok.io not found` | V |
| Pingdom | `*.stats.pingdom.com` | `Sorry, couldn't find the status page` | V |
| Read the Docs | `*.readthedocs.io` | `The link you have followed or the URL that you entered does not exist.` | V |
| Strikingly | `*.s.strikinglydns.com` | `PAGE NOT FOUND.` | V |
| Uberflip | provider CNAME | `The URL you've accessed does not provide a hub.` | V |
| UptimeRobot | `stats.uptimerobot.com` | `page not found` | V |
| SmugMug | `*.smugmug.com` | (no stable body fingerprint; probe claim flow) | V |

Two rows carry corrections worth stating plainly: **CloudFront and Fastly
are not takeover-able by claiming an alternate domain** — CloudFront rejects
a CNAME already associated with another distribution (`CNAMEAlreadyExists`)
and Fastly requires TLS/domain verification, so their unclaimed-serving
bodies are recon signals, not proof of claimability. **Azure is the highest-
yield modern surface**: deleting an App Service, Traffic Manager profile,
Cloud Service, storage account, or CDN endpoint frees a globally unique name
that resolves `NXDOMAIN`, and re-creating that exact name in any Azure
tenant rebinds the dangling CNAME.

TLS clues: certificate CN/SAN referencing the provider default host instead
of the custom subdomain, or the SNI returning the provider's wildcard cert
(`*.azurewebsites.net`, `*.github.io`) rather than a cert covering the
target name.

## Key Vulnerabilities

### Claim Third-Party Resource

- Create the resource with the exact required name:
  - Storage/hosting: S3 bucket "sub.example.com" (website endpoint)
  - Pages hosting: create repo/site and add the custom domain
  - Serverless/app hosting: create app/site matching the target hostname

Concrete claim step per high-yield provider (all require authorization and a
minimal ownership-proof payload only):

- **AWS S3** — the dangling CNAME points at `sub.example.com.s3-website-<region>.amazonaws.com`. Create a bucket named exactly `sub.example.com` in that region, enable static website hosting, and the CNAME now serves your content. Bucket names are globally unique, so the name being free is the takeover.
  ```bash
  aws s3api create-bucket --bucket sub.example.com --region us-east-1
  aws s3 website s3://sub.example.com/ --index-document index.html
  echo 'takeover-poc-<random>' > index.html && aws s3 cp index.html s3://sub.example.com/ --acl public-read
  ```
- **Azure (any service)** — dangling CNAME to `*.azurewebsites.net` / `*.trafficmanager.net` / `*.blob.core.windows.net` / `*.azureedge.net` resolving `NXDOMAIN`. Create the resource with the same first label in any subscription (`az webapp create --name <label>`, `az storage account create --name <label>`, `az network traffic-manager profile create --unique-dns-name <label>`). The global name is the claim.
- **GitHub Pages (E)** — create a repo, add a `CNAME` file containing `sub.example.com`, enable Pages. Claimable only when the domain is not already verified/held by another org account; GitHub now supports domain verification, so confirm the target org did not verify it.
- **Heroku (E)** — `heroku domains:add sub.example.com` on any app; historically unverified, now confirm the domain is not held.
- **Surge.sh** — `surge ./site sub.example.com` publishes to that hostname if unowned.
- **Bitbucket / GitLab / WordPress.com / Ghost / Readme / Pantheon / Canny / Help Scout / Help Juice** — sign up and add the custom domain / workspace slug matching the dangling label; the fingerprint providers marked **V** accept the binding without ownership proof.

For any **E** provider, the practical test is: attempt the binding in a
throwaway account and observe whether it is accepted or rejected with an
"already claimed / verify ownership" error. A rejection is the control
working; an acceptance is the takeover.

### CDN Alternate Domains

- Add the victim subdomain as an alternate domain on your CDN distribution if the provider does not enforce domain ownership checks
- Upload a TLS cert or use managed cert issuance

### NS Delegation Takeover

- If a child zone is delegated to nameservers under an expired domain, register that domain and host authoritative NS
- Publish records to control all hosts under the delegated subzone
- Detect lame delegation: the parent hands out NS records but those nameservers
  return `SERVFAIL`/`REFUSED` or their registrable domain is expired. Walk each
  delegated NS to its registrable domain and check registration state.
  ```bash
  # NS set for the delegated child zone, then check each NS domain's registration
  dig +short NS sub.example.com
  for ns in $(dig +short NS sub.example.com); do
    reg=$(echo "$ns" | rev | cut -d. -f1,2 | rev)
    echo "$ns -> $reg"; whois "$reg" | grep -iE 'no match|not found|expir|redemption|pendingDelete'
  done
  # confirm the delegation is actually lame (child unresolvable via that NS)
  dig @"$(dig +short NS sub.example.com | head -1)" sub.example.com SOA
  ```
- An expired NS registrable domain is a critical lead: registering it yields
  authoritative control of every host under the delegated label, not just one
  name.

### Mail Surface

- If MX points to a decommissioned provider, takeover could enable email receipt for that subdomain

Chain to account takeover where the subdomain (or the apex) still receives
mail addressed to real users: if `MX` points at a decommissioned or expired
mail provider/domain you can claim, stand up a catch-all and trigger
password resets for accounts at that domain. Receiving one reset link is
ATO. This is the highest-severity mail outcome — distinguish it explicitly
from merely being able to receive a tester-created message, and never read
unrelated correspondence (defer to `infrastructure_lifecycle`'s sensor/data-
handling rules if real third-party mail arrives).

### Cloud IP Reuse (Dangling A Records)

An `A`/`AAAA` record pointing at a public cloud IP that the org has since
released is claimable by cycling allocations until you receive that exact
IP. Unlike CNAME takeover there is no provider name to register — the
resource is the IP itself, drawn from the provider's shared pool.

- **Signal**: an `A` record inside a provider's published egress/EIP ranges
  (AWS `ip-ranges.json`, GCP/Azure ranges) that returns connection-refused,
  a default provider page, or a *different* tenant's service than the DNS
  name implies. Cross-check the PTR and the served TLS cert against the
  expected host.
- **Claim mechanic**: allocate-and-release in a loop in the target region
  until the pool hands you the target IP, then bind a listener/instance to
  it. AWS Elastic IPs and ephemeral public IPs, Azure public IPs, and GCP
  ephemeral/static IPs have all been shown reclaimable this way; the
  probability per allocation is small but the loop is cheap.
  ```bash
  # AWS EIP reclaim loop (authorized, target-region) — stop on the wanted IP
  TARGET=203.0.113.45
  while :; do
    A=$(aws ec2 allocate-address --domain vpc --query PublicIp --output text)
    [ "$A" = "$TARGET" ] && { echo "claimed $A"; break; }
    aws ec2 release-address --public-ip "$A"
  done
  ```
- **Impact is identical to CNAME takeover** once bound: serve content, a
  DV cert (the name resolves to you), or a service on the trusted origin.
  Rate it on the same trusted-origin-impact basis, and note the
  probabilistic claim in the finding.
- **False positive**: the IP still belongs to the org (a live but firewalled
  service) — confirm the IP is actually released, not merely filtered,
  before claiming.

## Advanced Techniques

### Blind and Cache Channels

- CDN edge behavior: 404/421 vs 403 differentials reveal whether an alt name is partially configured
- Cache poisoning: once taken over, exploit cache keys to persist malicious responses

### CT and TLS

- Use CT logs to detect unexpected certificate issuance for your subdomain
- For PoC, issue a DV cert post-takeover (within scope) to produce verifiable evidence

### OAuth and Trust Chains

- If the subdomain is whitelisted as an OAuth redirect/callback or in CSP/script-src, takeover elevates to account takeover or script injection

Concrete escalations once you control `sub.example.com` (these are what move
it from P4 defacement to P1/P2):

- **Cookie scope pivot / session fixation** — if the parent sets
  `Domain=.example.com` cookies, the taken-over subdomain can read them
  (session theft) or set an overriding cookie (cookie tossing / fixation)
  that the parent trusts. Prove by reading a real `Domain`-scoped cookie
  from JS on the controlled origin.
- **CORS trust** — if `api.example.com` reflects/allowlists
  `Access-Control-Allow-Origin: https://sub.example.com` with
  `Allow-Credentials: true`, host a page on the subdomain that
  `fetch(..., {credentials:'include'})` the API and exfiltrates the
  authenticated response.
- **CSP `script-src` gadget** — if the parent's CSP allows
  `*.example.com` or the exact subdomain, serve a script from the
  controlled origin and you have script execution in the parent's context
  (equivalent to stored XSS).
- **OAuth `redirect_uri` / SSO ACS** — if the IdP allows the subdomain as a
  redirect or SAML ACS URL, complete the flow to capture codes/tokens →
  account takeover. Chain with `oauth`/`authentication_jwt` for the token step.
- **SameSite=Lax bypass for CSRF** — a same-site subdomain is not
  cross-site, so a taken-over subdomain defeats `SameSite=Lax`/`Strict`
  cookie protections the parent relied on.

### Second-Order Subresource Loads

- A page on the target may `<script src>`, `<link href>`, load a font, or
  `fetch()` from a now-dangling subdomain. Take over that subdomain and you
  inject into every page that still imports it — no XSS on the main app
  needed. Grep crawled pages and JS bundles for hostnames under the org's
  zones, resolve each, and flag any that dangle.

### Verification Gaps

- Look for providers that accept domain binding prior to TXT verification
- Race windows: re-claim resource names immediately after victim deletion
- Monitor for the decommission event and claim inside the window. Watch the
  target's records/resources and fire the claim the moment the backing
  resource is deleted (before the DNS record is cleaned up):
  ```bash
  # cheap deletion monitor: alert when a tracked name starts to dangle
  while :; do
    dnsx -l tracked.txt -cname -resp -silent | \
      awk '{print $2}' | sed 's/[][]//g' | \
      dnsx -silent -rcode nxdomain && echo "DANGLING NOW: claim it" && break
    sleep 300
  done
  ```
  Pair with CT-log monitoring (certstream / crt.sh polling) so a newly issued
  or newly missing cert on a subdomain is an early decommission signal.

### Wildcards and Fallbacks

- Wildcard CNAMEs to providers may expose unbounded subdomains
- Fallback origins: CDNs configured with multiple origins may expose unknown-domain responses
- A dangling wildcard (`*.example.com CNAME <takeover-able provider>`) is a
  force multiplier: one claim of any label under it serves every non-existent
  subdomain, so you can mint an arbitrary trusted hostname on demand
  (`login.example.com`, `sso.example.com`) for phishing or to satisfy a CSP /
  OAuth allowlist keyed on `*.example.com`. Test by requesting a random label
  under the wildcard and checking it resolves into the provider's unclaimed
  response.

## Special Contexts

### Storage and Static

- S3/GCS/Azure Blob static sites: bucket naming constraints dictate whether a bucket can match hostname
- Website vs API endpoints differ in claimability and fingerprints

### Serverless and Hosting

- GitHub/GitLab Pages, Netlify, Vercel, Azure Static Web Apps: domain binding flows vary
- Most require TXT now, but historical projects may not

### CDN and Edge

- CloudFront/Fastly/Azure CDN/Akamai: alternate domain verification differs
- Some products historically allowed alt-domain claims without proof

### DNS Delegations

- Child-zone NS delegations outrank parent records
- Control of delegated NS yields full control of all hosts below that label

## Testing Methodology

1. **Enumerate subdomains** - Aggregate CT logs, passive DNS, and org inventory
2. **Resolve DNS** - All RR types: A/AAAA, CNAME, NS, MX, TXT; keep CNAME chains
3. **HTTP/TLS probe** - Capture status, body, error text, Server headers, certificate SANs
4. **Fingerprint providers** - Map known "unclaimed/missing resource" signatures
5. **Attempt claim** (with authorization) - Create missing resource with exact required name
6. **Validate control** - Serve minimal unique payload; confirm over HTTPS

## Validation

1. Before: record DNS chain, HTTP response (status/body length/fingerprint), and TLS details
2. After claim: serve unique content and verify over HTTPS at the target subdomain
3. Optional: issue a DV certificate (legal scope) and reference CT entry as evidence
4. Demonstrate impact chains (CSP/script-src trust, OAuth redirect acceptance, cookie Domain scoping)

## Severity

- Score severity based on current claimability plus trusted-origin impact, not just a provider-branded error page
- When evaluating severity, use `web_search` (if available) for the exact provider/product to confirm whether it now enforces subdomain takeover prevention such as TXT/custom-domain ownership verification or reserved-hostname protections; if search is unavailable, do not treat that absence as evidence that the provider prevents claiming
- If you have positively confirmed the provider currently prevents third-party claiming and you cannot bypass that control, treat the finding as low severity rather than a confirmed takeover — an unconfirmed provider control is not grounds for downgrading
- Reserve high/critical severity for cases where you can claim the resource or strongly prove claimability and show meaningful impact such as OAuth redirect abuse, cookie scope abuse, CSP trust, email receipt, or NS delegation control. E.g. Elastic Beanstalk takeovers are still generally legitimate.

## False Positives

- "Unknown domain" pages that are not claimable due to enforced TXT/ownership checks
- Provider-branded default pages for valid, owned resources (not a takeover)
- Soft 404s from your own infrastructure or catch-all vhosts

## Impact

- Content injection under trusted subdomain: phishing, malware delivery, brand damage
- Cookie and CORS pivot: if parent site sets Domain-scoped cookies or allows subdomain origins
- OAuth/SSO abuse via whitelisted redirect URIs
- Email delivery manipulation for subdomain

## Pro Tips

1. Build a pipeline: enumerate (subfinder) → resolve (dig) → probe (httpx) → fingerprint (nuclei/custom) → verify claims
2. Maintain a current fingerprint corpus; provider messages change frequently
3. Prefer minimal PoCs: static "ownership proof" page and, where allowed, DV cert issuance
4. Monitor CT for unexpected certs on your subdomains
5. Eliminate dangling DNS in decommission workflows first
6. For NS delegations, treat any expired nameserver domain as critical
7. Use CAA to limit certificate issuance while you triage

## Tooling

Detection tools are fingerprint scanners — they flag a *candidate* against a
built-in signature corpus. Every hit still needs the manual claimability
confirmation in Severity before it is a finding.

- **dnsReaper** (punk-security) — the most current scanner; ~50 provider
  signatures, fast, takes many input formats and cloud-account imports. Runs
  the full "does this dangle and is the provider takeover-able" check:
  ```bash
  docker run punksecurity/dnsreaper file --filename subs.txt
  # or resolve from a zone/records file; --signature <name> to scope one provider
  ```
- **subzy** (LukaSikic) — Go single-binary CNAME-takeover checker with an
  auto-updating fingerprint list and an SSL/verify-before-report option:
  ```bash
  subzy run --targets subs.txt --concurrency 50 --hide_fails --verify_ssl
  ```
- **subjack** (haccer) — older Go checker; still useful, but its fingerprint
  file is stale — update `fingerprints.json` before relying on it:
  ```bash
  subjack -w subs.txt -t 50 -ssl -c fingerprints.json -o results.txt
  ```
- **nuclei** — `http/takeovers/` template set for triage inside an existing
  nuclei pipeline (`nuclei -l subs.txt -t http/takeovers/`). Good for breadth,
  weaker than dnsReaper/subzy on edge cases.
- **dnsx / httpx** (ProjectDiscovery) — the resolve + probe primitives the
  scanners are built on; use directly (as in the Enumeration Pipeline) when you
  need the raw CNAME chain, PTR, or served cert rather than a yes/no verdict.

Cross-check at least two scanners plus a manual probe — signature corpora drift
in opposite directions (one flags a now-protected provider, another misses a
newly-vulnerable one).

## Summary

Subdomain safety is lifecycle safety: if DNS points at anything, you must own and verify the thing on every provider and product path. Remove or verify—there is no safe middle.
