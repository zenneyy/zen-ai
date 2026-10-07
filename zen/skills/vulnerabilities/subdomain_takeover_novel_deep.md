---
name: subdomain-takeover-novel-deep
description: 2024-2026 current-frontier subdomain-takeover boundaries — AWS S3 account-regional-namespace, Azure DNS alias scope, App Service asuid preclaim, and classic cloud-service tenant reservation — scoping which historical patterns remain claimable.
sibling: subdomain_takeover
load_when: scan_mode == "deep"
---

# Subdomain Takeover — Current Frontier Boundaries (2024–2026)

Base `subdomain_takeover.md` owns the enumeration pipeline, the ~50-provider V/E/N fingerprint table, the primary per-provider claim recipes, and the testing/severity framing. `subdomain_takeover_advanced_deep.md` owns the chain primitives (cookie, CORS, CSP, OAuth, SameSite, service worker, mobile deep-link, NS delegation, cloud-IP reuse, MX/mail, DKIM/.well-known, SAML metadata, CDN cache poisoning, wildcard). This file owns the 2024–2026 provider-side boundary changes that narrow the live claimability frontier for AWS S3 and Azure — exactly the version-boundary-as-finding material that determines which historical fingerprints remain reachable on net-new deployments and which remain reachable only against legacy targets.

## AWS S3 Account-Regional-Namespace Boundary

**Primitive.** AWS launched account-regional-namespace S3 buckets on 2026-03-12, scoping bucket names to `<name>-<account-id>-<region>-an` instead of the legacy global namespace `<name>`. The legacy global-namespace bucket is still globally unique and *still claimable after deletion* — a dangling CNAME `sub.example.com → mybucket.s3.amazonaws.com` where `mybucket` was deleted remains takeover-able by any AWS account that creates a bucket named exactly `mybucket`. The frontier narrows for *new* buckets: an account-regional-namespace bucket `mybucket-123456789012-us-east-1-an` is scoped to account 123456789012 and cannot be squatted. Legacy and new namespaces coexist on the same account; existing global-namespace buckets have no migration path.

**Preconditions.** All of: (i) the dangling CNAME points at the legacy global namespace (`<label>.s3.amazonaws.com` or `<label>.s3-website-<region>.amazonaws.com`), NOT at a `-<account-id>-<region>-an` suffix; (ii) the exact bucket name is currently free (any AWS account can run `aws s3api head-bucket --bucket <label>` and receive `404 Not Found` rather than `403 Forbidden`); (iii) the attacker has an AWS account in the required region (bucket region matters for the website-endpoint variant).

**Attack recipe.**

```bash
# Confirm the dangling target is legacy-namespace, not account-regional:
dig +short sub.example.com                   # CNAME mybucket.s3-website-us-east-1.amazonaws.com
# Legacy namespace: the hostname has NO -<accountid>-<region>-an segment.

# Confirm the name is free (404, not 403):
aws s3api head-bucket --bucket mybucket --region us-east-1 2>&1 | head -1
# "Not Found" → claimable. "Forbidden" → bucket exists in another account.

# Claim:
aws s3api create-bucket --bucket mybucket --region us-east-1
aws s3 website s3://mybucket/ --index-document index.html
aws s3api put-public-access-block --bucket mybucket \
  --public-access-block-configuration BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
echo 'proof-of-ownership' > index.html
aws s3 cp index.html s3://mybucket/ --acl public-read
```

For account-regional-namespace targets (`mybucket-123456789012-us-east-1-an`), the create fails with `BucketAlreadyExists` even across accounts because the segment includes the owning account ID — the name encodes ownership. No claim path exists; the fingerprint is a dead end.

**Confirmation signal.** `curl -s https://sub.example.com/` returns `proof-of-ownership`; TLS SNI resolves to the S3 website endpoint; the CNAME chain terminates in the claimed bucket. Legacy-namespace proof: the host suffix is `.s3.amazonaws.com` or `.s3-website-<region>.amazonaws.com` without the `-<accountid>-<region>-an` suffix; account-regional-namespace rejection: `aws s3api create-bucket` returns `BucketAlreadyExists` even for a name the dig NXDOMAIN suggested was free, because the account-regional segment reserves the name.

**Impact.** Legacy-namespace S3 buckets remain the single highest-yield modern-AWS takeover surface — the fingerprint table's `V` rating for `*.s3.amazonaws.com` holds for every target created before the account-regional-namespace rollout and for every account that still chooses the legacy namespace (opt-in by default; account-regional is a per-bucket choice at creation time). Routes to `subdomain_takeover_advanced_deep.md § Cookie Scope Pivot` and § CSP `script-src` Gadget for post-claim chains. The practical class abstraction: **the global namespace is now a legacy surface; new deployments that choose account-regional cut off this class, but every bucket created before March 2026 is still in scope and no migration is available.**

## Azure DNS Alias Record Scope and asuid Preclaim

**Primitive.** Azure DNS alias records are a lifecycle-coupled DNS record type: the alias target is a reference to an Azure resource (not a hostname), and the DNS record is automatically updated when the backing resource changes — including dropping to empty when the backing resource is deleted. Alias records close the dangling-DNS primitive for the specific resource types they support. As of 2026-07-24, alias records support exactly **four resource types**: Azure Front Door, Traffic Manager, CDN endpoints, and Public IPs. Every other FQDN-bearing Azure service (Blob Storage, App Service, API Management, Container Instance, App Service Slots, and more) is outside this protection, and traditional dangling-DNS applies. A complementary preclaim mechanism exists for Azure App Service: creating a `asuid.{subdomain}` TXT record with the subscription's domain-verification ID blocks any *other* Azure subscription from validating that custom domain, so an attacker who provisions an App Service with the right name can create it in `*.azurewebsites.net` but cannot bind the custom hostname.

**Preconditions (claim-side).** All of: (i) the dangling record is a CNAME, not an alias record (`az network dns record-set cname show -z example.com -n sub` returns a CNAME; `az network dns record-set a show -z example.com -n sub` with `--query targetResource` is empty); (ii) the pointed-at Azure resource type is NOT in the four protected types (Front Door, Traffic Manager, CDN endpoints, Public IPs); (iii) the target subdomain does NOT have a corresponding `asuid.{subdomain}` TXT record pre-published by the owning subscription (dig `TXT asuid.sub.example.com`; a non-empty TXT with a valid subscription verification ID means the custom-domain binding is pre-reserved and the attacker's App Service cannot claim the custom hostname even if the global name is free); (iv) the Azure resource type has an owner-choice-free global namespace (any subscription can claim `<label>.azurewebsites.net` if it is free).

**Preconditions (preclaim-defense recognition).** All of: (i) the attacker provisions the matching Azure resource (e.g. an App Service named `label.azurewebsites.net`), observes that creation *succeeds*, and the dangling CNAME now resolves to the attacker-owned resource; (ii) attempting to bind the custom hostname via the Azure portal / `az webapp config hostname add` fails with `Custom domain verification ID does not match` or `The CNAME record for custom domain is already pointing to another App Service` — this means the owner published an `asuid` TXT and the custom-hostname claim is blocked; (iii) the attacker still controls the default `.azurewebsites.net` host but cannot receive traffic for the dangling custom name.

**Attack recipe.**

```bash
# Classify the pointed-at Azure resource type to decide if alias-record protection applies:
dig +short sub.example.com | grep -oE '(azurewebsites\.net|azurefd\.net|trafficmanager\.net|azureedge\.net|azurecloudapp|cloudapp\.net|blob\.core\.windows\.net|azure-api\.net)' | head -1

# Alias-protected types (claim will not grant traffic):
#   azurefd.net, trafficmanager.net, azureedge.net (CDN endpoints), Public-IP FQDNs
# Dangling-reachable types (claim grants traffic once the global name is free AND no asuid):
#   azurewebsites.net, blob.core.windows.net, azure-api.net, cloudapp.azure.com,
#   container-instances, App Service Slots, static-sites

# Check for asuid preclaim before attempting the App Service variant:
dig +short TXT asuid.sub.example.com
# non-empty → preclaimed by the owning subscription, custom-hostname bind blocked.
# empty → the owner did not preclaim and the custom-hostname bind will succeed if
# the attacker's subscription creates the matching App Service.

# Claim (App Service variant):
az webapp create -g <rg> -p <plan> -n <label>   # <label> matches the dangling CNAME host-left-of-azurewebsites.net
az webapp config hostname add -g <rg> --webapp-name <label> --hostname sub.example.com
# Succeeds iff no asuid TXT is published. The dangling CNAME now routes to the attacker's App Service.
```

**Confirmation signal.** For dangling-reachable types without `asuid` TXT: `curl -s https://sub.example.com/` returns the attacker-served content; the Azure portal shows the custom-hostname binding as `Verified`. For asuid-preclaimed targets: the create succeeds in `*.azurewebsites.net` but the custom-hostname binding fails with the explicit asuid-mismatch error — this is a measured negative result and the finding is "custom-hostname preclaimed, cannot receive traffic for the dangling name." For alias-protected types: `dig +short` returns `NXDOMAIN` as soon as the backing resource is deleted (no dangling record ever appears), so the primitive is unreachable at the DNS layer.

**Impact.** Claimable Azure types (App Service, Blob, APIM, Container Instance, Static Web Apps) remain the modern-Azure takeover high-yield surface *when `asuid` is not published*. The practical class abstractions: (1) **alias records close four types but not the rest** — the fingerprint table rows for `*.azurewebsites.net` / `*.blob.core.windows.net` / `*.azure-api.net` / `*.cloudapp.net` are still live, the rows for `*.azurefd.net` / `*.trafficmanager.net` / `*.azureedge.net` are closed at the DNS layer; (2) **`asuid` is a preclaim defense** that even without alias support closes App Service custom-hostname claims — a defender's checklist item, and an attacker's early-exit when the TXT is present. Routes to `subdomain_takeover_advanced_deep.md § Cookie Scope Pivot` and § SAML SP Metadata Hijack for post-claim chains against the un-preclaimed, non-alias-protected types.

## Azure Classic Cloud Service Tenant-Reservation Window

**Primitive.** Classic Azure cloud service DNS names across the four sovereign zones — `*.cloudapp.net`, `*.chinacloudapp.cn`, `*.usgovcloudapp.net`, `*.azurecloudapp.de` — are reserved to the originating subscription's Microsoft Entra tenant for a bounded window after the backing cloud service is deleted. Within that window, no other subscription can claim the name; outside the window, any Azure subscription can claim it. The reservation window is a per-tenant lifecycle guarantee that creates an explicit version-boundary-as-finding: a classic-cloud-service dangling target is reachable only after the reservation lapses, and the attacker's timing determines reachability.

**Preconditions.** All of: (i) the dangling CNAME points at a classic cloud service hostname in one of the four sovereign zones; (ii) the backing cloud service has been deleted (the hostname returns NXDOMAIN); (iii) the tenant-reservation window has passed since deletion (observable by the claim either succeeding immediately or returning `name is reserved for another subscription` within the window); (iv) the attacker's subscription is in a tenant permitted to create resources in the matching sovereign cloud (Azure global, China, US Gov, or Germany) — cross-sovereign claims are blocked at the control-plane layer.

**Attack recipe.**

```bash
# Identify a classic cloud service dangling target:
dig +short sub.example.com | grep -oE '[^.]+\.(cloudapp\.net|chinacloudapp\.cn|usgovcloudapp\.net|azurecloudapp\.de)$'

# Attempt the claim; the response tells you whether the reservation window is active:
az deployment group create -g <rg> \
  --template-file classic-cloud-service.json \
  --parameters cloudServiceName=<label>
# Success → window has passed, the attacker owns the name.
# "name is reserved for the originating tenant" → window still active; retry later.
# "cross-sovereign create" → the sovereign cloud blocks the claim entirely.
```

The reservation window is bounded but public documentation does not fix an exact number of days — operational observations place it in the single-digit-to-tens-of-days range depending on the sovereign cloud, and the behavior is subject to change. Monitor the target with a periodic claim attempt; the first attempt that succeeds marks the window boundary for that specific name, which is itself a measurable datapoint.

**Confirmation signal.** The `az deployment group create` succeeds (or the equivalent classic-cloud-service create via REST), and the DNS CNAME now resolves to the attacker-owned classic cloud service. For a *negative* result (window still active): the error explicitly names the originating-tenant reservation, which is a measured confirmation that the reservation guarantee is in force for the specific name — a first-class finding for defenders tracking which names remain protected.

**Impact.** Classic cloud service takeovers remain reachable but only after the reservation window — a timing-dependent primitive, not an evergreen one. The practical class abstraction: **sovereign-cloud resource lifecycle introduces a measurable reservation window that gates reachability; the attacker who monitors this window captures the moment the reservation lapses, and the defender who tracks the same window knows precisely when their legacy classic-cloud-service names re-enter the global claimable pool.** Routes to `subdomain_takeover_advanced_deep.md § Race Window and Decommission Monitoring` for the general monitor-and-fire framing applied to this specific reservation surface.

## Measured Current-Frontier Boundary Table

A single boundary table for the primitives above, measured against the live Azure Learn and AWS Security documentation as of 2026-10-03 (persisted in the batch artifact dir). Each row names the surface, the current claim-time boundary, and whether the legacy fingerprint remains live.

| Surface | Current Claim-Time Boundary | Legacy Fingerprint |
|---|---|---|
| S3 legacy global namespace | Free name after bucket delete → claimable | V (live) |
| S3 account-regional namespace | Name encodes account ID → non-squattable | — (new surface) |
| Azure Front Door | Alias record drops to empty on resource delete → DNS-layer unreachable | N (closed) |
| Azure Traffic Manager | Alias record drops to empty → DNS-layer unreachable | N (closed) |
| Azure CDN endpoint | Alias record drops to empty → DNS-layer unreachable | N (closed) |
| Azure Public IP (FQDN) | Alias record drops to empty → DNS-layer unreachable | N (closed) |
| Azure App Service (no asuid) | Free `*.azurewebsites.net` + no asuid TXT → claimable | V (live, pre-check asuid) |
| Azure App Service (asuid preclaimed) | Create succeeds in `*.azurewebsites.net` but custom-hostname bind blocked | N (preclaimed) |
| Azure Blob Storage | Free `*.blob.core.windows.net` → claimable | V (live) |
| Azure API Management | Free `*.azure-api.net` → claimable | V (live) |
| Azure Container Instance | Free `*.<region>.azurecontainer.io` → claimable | V (live) |
| Azure Static Web Apps | Free `*.<region>.<n>.azurestaticapps.net` → claimable | V (live, no asuid-equivalent documented) |
| Azure classic cloud service (global) | Tenant reservation then global pool → claimable after window | V (live, timing-gated) |
| Azure classic cloud service (China/USGov/DE) | Tenant reservation within sovereign cloud only | V (live, timing-gated + sovereign-scoped) |
| AWS CloudFront | `CNAMEAlreadyExists` enforcement blocks CNAME claims | N (not takeover-able by alt-domain claim) |
| AWS Fastly | TLS/domain verification blocks CNAME claims | N (not takeover-able by alt-domain claim) |

The rows marked `N` and `V` in the base's ~50-provider fingerprint table remain the ground truth for providers not listed above; the rows here are the 2026-current corrections or additions. The table resolves one tangle in particular: the AWS CloudFront and Elastic Beanstalk refutation from the Batch 10 research — CloudFront remains closed (as the base already recorded), and Elastic Beanstalk is not re-added as a claimable surface despite legacy prose that suggested it; a dangling Elastic Beanstalk CNAME now requires exact-environment-name reuse within the same AWS region, and the environment-name reservation behavior is sufficiently close to Azure classic cloud service's that defenders should treat it with the same timing-window skepticism rather than assuming free claimability.

## Chaining Surface and Frontier Honesty

The 2026-current boundary findings interact with the chain primitives in `subdomain_takeover_advanced_deep.md` by scoping *which hosts* the chain primitives can be fired against. The chain primitives themselves (cookie, CORS, CSP, OAuth, SameSite, service worker, mobile deep-link, NS delegation, cloud IP reuse, MX/mail, DKIM/.well-known, SAML metadata, CDN cache poisoning, wildcard) remain fully reachable on every surface marked `V` or legacy-live in the table above. The frontier narrowing applies at the *claim step*, not the chain step — a successful claim against an un-protected surface still unlocks every downstream chain the advanced sibling catalogs.

The live cloud-takeover frontier for S3 and Azure is narrower than its history in a specific way: the big public-cloud providers have moved to lifecycle-coupled DNS record types (alias records) and per-domain preclaim mechanisms (`asuid`) that close a subset of the historically-claimable providers at the DNS layer or at the custom-hostname-bind layer. The historical fingerprint table remains correct for legacy targets, but the current-frontier reachability requires the per-surface classifier the measured table above provides. This is the escape-hatch disposition for the novel tier: the frontier of *new* claimable classes is thin because the primitives that remain are refinements of the base, and the measurement is in the boundary table rather than in new primitive classes.

## Detection and Verification Methodology

The novel-tier detection work is the per-surface classifier that distinguishes alias-protected from dangling-reachable, and that detects `asuid` preclaim before attempting the chain:

- **Classify the pointed-at Azure resource type first.** The suffix of the CNAME target (`.azurefd.net` / `.trafficmanager.net` / `.azureedge.net` / public-IP FQDN) is the alias-protected set; `.azurewebsites.net` / `.blob.core.windows.net` / `.azure-api.net` / `.cloudapp.net` / sovereign-cloud variants are the un-protected set. The classification is a one-line `grep` against the resolved CNAME.
- **Query `asuid.{subdomain}` TXT before provisioning.** A non-empty TXT with the owning subscription's verification ID is a measured negative — the custom-hostname bind will fail even if the global name is free. Report this as a "preclaimed, non-exploitable" finding; it is still useful intelligence about the owner's defensive posture.
- **Classify the S3 target namespace before the create attempt.** The CNAME target with no `-<accountid>-<region>-an` suffix is legacy-namespace and reachable; the suffix encodes ownership and the create will fail with `BucketAlreadyExists` across accounts.
- **For classic cloud service, run a periodic claim attempt rather than a single probe.** The reservation window is bounded but not fixed; the first attempt that succeeds measures the window boundary for the specific name and is a first-class finding for defender inventorying.
- **Elastic Beanstalk environment-name reuse is a different class and should not be reported as a `V` fingerprint without a successful claim.** The 2026 research refuted the "globally claimable" framing; treat it as a timing-and-region-gated class, like classic cloud service, and confirm with a measured claim attempt before escalating severity.

## False-Positive Discipline

- **Alias-protected target with a non-NXDOMAIN response is a misread, not an exploitable dangling.** If the resolved record is an alias record (not a CNAME) and the backing resource exists, the record resolves normally; if the backing resource is deleted, the alias drops to empty and the record ceases to exist. There is no window during which the alias dangles with a provider-unclaimed-serving body — the control is at the DNS layer, not at the HTTP layer. Confirm the record type (`az network dns record-set a show --query targetResource.id`) before claiming the fingerprint is reachable.
- **`asuid` TXT present means the custom-hostname bind will fail.** The `*.azurewebsites.net` global name can still be created in any Azure subscription (that is not the same as claiming the custom hostname), but the custom-hostname bind step fails explicitly. Reporting a successful global-name create as a takeover is a false positive; the finding is only real if the custom-hostname bind also succeeds and the attacker-controlled resource serves traffic for the dangling CNAME.
- **`BucketAlreadyExists` across accounts on an account-regional-namespace target is the control working, not a race lost.** The account-regional segment encodes ownership; retrying the create will never succeed. Classify the namespace first; only legacy-global-namespace targets are reachable.
- **Classic cloud service `name is reserved for another tenant` is a timing signal, not a permanent block.** The reservation window is bounded; retry on a schedule and the window will eventually lapse. Reporting the first-attempt reservation failure as a `N` fingerprint is a false negative.
- **CloudFront `CNAMEAlreadyExists` is a permanent block for the alt-domain claim path.** The base's fingerprint table marks CloudFront as `N`, and the Batch 10 research explicitly refuted the "CloudFront remains globally claimable" framing. The alt-domain-claim path on CloudFront is closed; the only CloudFront takeover primitives are the second-order subresource load (`subdomain_takeover_advanced_deep.md`) and distribution-wildcard-origin confusion, neither of which belongs under the alt-domain fingerprint.

The 2026-current frontier of *new* subdomain-takeover primitive classes is thinner than the historical catalog because the big providers have moved to lifecycle-coupled DNS types and per-domain preclaim defenses that close subsets of the historically-claimable set — the catalog of claimable patterns on net-new deployments is narrower than its history, and the measurable work is in the boundary table above rather than in new chain primitives.

## Summary

AWS and Azure both introduced provider-side mechanisms in 2024–2026 that close subsets of the historically-claimable subdomain-takeover surface — S3 account-regional-namespace scopes bucket names to the owning account, Azure DNS alias records lifecycle-couple four specific resource types, and the Azure App Service `asuid` preclaim blocks cross-subscription custom-hostname binds — while the classic cloud service tenant-reservation window gates reachability on a timing basis. The practical net is that the historical fingerprint table remains the ground truth for legacy targets, but the current-frontier reachability requires a per-surface classifier (CNAME suffix, `asuid` TXT presence, legacy-vs-account-regional-namespace discrimination for S3) before the base's claim recipes apply. Chain primitives in the advanced sibling remain fully reachable on every surface still marked `V` or legacy-live, so the frontier narrowing is at the claim step rather than at the chain step, and the measurable work for this class in 2026 is the boundary table above, not a new catalog of chain primitives.
