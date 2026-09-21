---
name: asset-discovery-cloud-deep
description: Advanced cloud runtime, serverless, and edge platform surface enumeration. Loaded automatically by deep scan mode as a companion to asset_discovery.md. Covers AWS Lambda/Function URLs/Amplify/AppRunner/ECS/EKS runtime surface, Azure Functions/Container Apps/Static Web Apps/AKS, GCP Cloud Run/Cloud Functions/App Engine/GKE, Cloudflare Workers/Pages, Vercel/Netlify Edge, and modern edge platforms (Deno Deploy, Fly.io, Railway, Render). Includes cloud IAM federation, ephemeral compute discovery, container ingress patterns, and cloud metadata reconnaissance signals for 2024-2026.
sibling: asset_discovery
load_when: scan_mode == "deep"
---

# Asset Discovery — Cloud Runtime (Deep)

This is the deep sibling to `asset_discovery` for cloud runtime surface. The base file covers passive host discovery and cloud-range attribution — mapping which provider owns an IP. This file covers the layer above that: the provider-specific runtime endpoints an org actually ships — serverless URLs, container ingress, storage endpoints, edge deployments, federation trust, and ephemeral compute — the surface where cloud-native bugs (SSRF-to-metadata, IAM misconfiguration, storage abuse, admission-webhook exploitation) actually live.

It loads only in deep scan mode. In standard mode the base file's cloud-range attribution is enough; deep mode pulls this in for per-provider runtime enumeration.

One theme runs through every platform below: these services are fronted by provider **wildcard certificates** (`*.on.aws`, `*.run.app`, `*.vercel.app`, `*.workers.dev`), so individual serverless/edge subdomains do **not** appear in certificate transparency. CT reveals only **custom domains** bound to a platform (those get per-name certs) — correlate those back to the platform via CNAME and response headers. For the platform-default subdomains, discovery relies on source-code mining (per `application_enumeration`), passive DNS, provider APIs when a token leaks, and — where the URL format is deterministic (Cloud Run, App Engine) — direct prediction. Do not assume a CT sweep found the serverless surface; it did not.

The other recurring workflow: **if any cloud credential leaks on the target** (a key in a bundle, a token in a `.env`, a leaked CI secret), the provider CLI enumerates the account in seconds and reveals surface no external probe can — run it before the credential rotates. Every provider section below gives the credentialed CLI path alongside the unauthenticated one.

Two other deep siblings are complementary but out of scope here: `asset_discovery_saas_deep` (SaaS/IdP tenant discovery and modern platform correlation) and `asset_discovery_historical_deep` (historical, time-series, and OSINT-derived discovery). All three load in deep mode. URL patterns below verified 2026-09-13; where a provider format is changing, both current and legacy forms are given.

## Platform Fingerprinting

Before enumerating a provider you have to know which one a discovered host belongs to — most runtime hosts sit behind a custom domain, so the platform is not in the name. Two signals resolve it: the CNAME chain and the response headers. Fingerprint every custom domain before assigning it to a section below.

Response-header tells (`curl -sI <host>`):

| Header signal | Platform |
|---|---|
| `x-amzn-RequestId` (+ `x-amz-apigw-id`) | AWS API Gateway |
| bare `x-amzn-*`, no `apigw` | Lambda Function URL / App Runner |
| `x-amz-cf-id` + `via: ...cloudfront.net` | AWS CloudFront (origin behind it) |
| `server: Google Frontend` + `x-cloud-trace-context` | GCP Cloud Run / App Engine / GCLB |
| `x-azure-ref` | Azure Front Door / App Service |
| `x-aspnet-version` / `x-powered-by: ASP.NET` | Azure App Service (or IIS origin) |
| `server: Vercel` + `x-vercel-id` | Vercel |
| `server: Netlify` | Netlify |
| `cf-ray` + `server: cloudflare` | Cloudflare (Workers/Pages/proxy) |
| `fly-request-id` | Fly.io |
| `x-render-origin-server` | Render |

CNAME-chain tells (`dig +short <host>`, keep the whole chain):

```bash
dig +short CNAME <custom-domain>    # follow every hop
```

- `*.cloudfront.net` → CloudFront; `*.elb.amazonaws.com` → AWS ELB/ALB/NLB; `*.awsglobalaccelerator.com` → Global Accelerator
- `*.azurefd.net` / `*.trafficmanager.net` / `*.azureedge.net` → Azure Front Door / Traffic Manager / CDN
- `ghs.googlehosted.com` / `c.storage.googleapis.com` → GCP (App Engine/Firebase custom domain / GCS website)
- `cname.vercel-dns.com` → Vercel; `*.netlify.app` → Netlify; `*.pages.dev` → Cloudflare Pages
- a bare cloud IP with no CNAME → attribute via the base file's cloud-range feeds, then port-sweep

A custom domain whose CNAME points at a platform default that no longer exists (deleted Vercel project, released Amplify branch, removed Pages project) is a subdomain-takeover lead — hand it to `subdomain_takeover`.

## AWS Runtime Surface

AWS runtime endpoints are region-scoped and mostly wildcard-fronted. Enumerate per region — a target with `us-east-1` production frequently has `eu-west-1`/`us-west-2` staging on the same account with weaker controls. Credentialed enumeration covers all regions at once:

```bash
for r in us-east-1 us-west-2 eu-west-1 eu-central-1 ap-southeast-1; do
  aws lambda list-functions --region "$r" --query 'Functions[].FunctionName'
  aws apigatewayv2 get-apis --region "$r" --query 'Items[].ApiEndpoint'
  aws apprunner list-services --region "$r" 2>/dev/null
done
```

### Lambda Function URLs

**Pattern**: `https://<url-id>.lambda-url.<region>.on.aws/`, where `<url-id>` is a 32-char lowercase-hex-ish id unique per function+alias. Opt-in per function — most functions have no URL, so absence means nothing.

CT is low-yield here — the endpoint uses an AWS-managed `*.lambda-url.<region>.on.aws` wildcard, so individual `<url-id>` values are not in CT logs. Source mining is the highest-yield path; the URL is almost always hardcoded in a client bundle or mobile app:

```bash
grep -rhoE 'https://[a-z0-9]+\.lambda-url\.[a-z0-9-]+\.on\.aws[^"'"'"' ]*' bundles/ | sort -u
# credentialed: which functions actually have a URL, and its auth mode
aws lambda list-functions --query 'Functions[].FunctionName' --output text | tr '\t' '\n' | \
  while read fn; do aws lambda get-function-url-config --function-name "$fn" 2>/dev/null \
    --query '{url:FunctionUrl,auth:AuthType}'; done
curl -sI https://<url-id>.lambda-url.us-east-1.on.aws/ | grep -iE 'x-amzn-|server'
```

**Confirm**: `x-amzn-RequestId` / `x-amzn-Remapped-*` headers on the response confirm Lambda behind the URL. A `403 {"Message":"Forbidden"}` with `x-amzn-ErrorType` is `AuthType: AWS_IAM` (SigV4 required); a normal app response is `AuthType: NONE` (publicly invokable) — the latter is the finding.

**Gotcha**: `AuthType: NONE` URLs are internet-open by design; the bug is what the function does with unauthenticated input, not the URL itself. Feed it to the app-layer hunters (`application_enumeration`, then the sink-specific skill).

### API Gateway REST (v1) and HTTP (v2) APIs

**Pattern** (both): `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/`. `<api-id>` is 10 lowercase-alphanumeric chars. The default `<stage>` is often the deployment name (`prod`, `dev`, `v1`) — enumerate stages, not just the base.

```bash
grep -rhoE '[a-z0-9]{10}\.execute-api\.[a-z0-9-]+\.amazonaws\.com[^"'"'"' ]*' bundles/ | sort -u
# credentialed: v1 (REST) and v2 (HTTP) are separate services
aws apigateway get-rest-apis --query 'items[].{id:id,name:name}'
aws apigatewayv2 get-apis --query 'Items[].{id:ApiId,ep:ApiEndpoint}'
# stage probing on a discovered api-id
for s in prod dev test stage staging v1 v2 beta default; do
  echo "$s $(curl -s -o /dev/null -w '%{http_code}' https://<api-id>.execute-api.<region>.amazonaws.com/$s/)"; done
```

**Confirm**: `x-amzn-RequestId` on any response. v2 (HTTP API) commonly serves the `$default` stage at the root (no stage path) with lean headers; v1 (REST) requires an explicit stage and adds `x-amz-apigw-id` and per-stage behaviors.

**Gotcha**: a non-prod stage on the same `<api-id>` often exposes debug behavior or a looser Lambda authorizer than prod — always enumerate stages beyond the one in the bundle.

### API Gateway Private Endpoints

**Pattern**: `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>` but reachable only through an `execute-api` interface VPC endpoint, keyed by an `aws:SourceVpce` resource-policy condition. From a network position inside the VPC or an SSRF/RCE foothold:

```bash
aws ec2 describe-vpc-endpoints --filters Name=service-name,Values='*execute-api*' \
  --query 'VpcEndpoints[].{id:VpcEndpointId,dns:DnsEntries[0].DnsName}'
curl -s https://<api-id>.execute-api.<region>.vpce.amazonaws.com/<stage>/ -H 'x-apigw-api-id: <api-id>'
```

**Gotcha**: a private API is invisible externally — it surfaces only from a foothold; catalog it as an internal chain target, not an external host.

### Amplify Hosting

**Pattern**: `https://<branch>.<app-id>.amplifyapp.com`, `<app-id>` a `d`-style id (`d1a2b3c4e5f6g7`). Production is usually `main`/`master`; **preview/feature branches** get their own subdomain and are routinely less-hardened, use dev backends, and skip WAF.

```bash
grep -rhoE '[a-z0-9.-]+\.amplifyapp\.com' bundles/ | sort -u
# credentialed: every app + branch, including deleted-but-serving branches
aws amplify list-apps --query 'apps[].{id:appId,name:name}'
aws amplify list-branches --app-id <app-id> --query 'branches[].{b:branchName,url:branchName}'
# unauth: guess branches once app-id is known
for b in main master develop staging dev preview test release; do
  echo "$b $(curl -s -o /dev/null -w '%{http_code}' https://$b.<app-id>.amplifyapp.com)"; done
```

**Confirm**: Amplify serves an `x-amz-cf-*` (CloudFront) header set plus an Amplify-specific `x-cache`; a `200` on a guessed branch host is a live branch.

**Gotcha**: branch names beyond the obvious come from the org's public repos — mine repo branch lists and feed them here.

### App Runner

**Pattern**: `https://<random>.<region>.awsapprunner.com`. Less-enumerated than Lambda/API Gateway and rarely in wordlists — source mining, header fingerprinting, and the credentialed `aws apprunner list-services` are the reliable paths.

```bash
grep -rhoE '[a-z0-9]+\.[a-z0-9-]+\.awsapprunner\.com' bundles/ | sort -u
aws apprunner list-services --query 'ServiceSummaryList[].{name:ServiceName,url:ServiceUrl}'
```

**Confirm**: `x-amzn-*` headers. A `503`/pending is a cold or paused service, not absence — retry before concluding.

### ECS Fargate and EC2 Public IPs

Fargate tasks get a public IP only when `assignPublicIp: ENABLED`. These are raw IPs, not DNS names.

```bash
# credentialed: task -> ENI -> public IP
for c in $(aws ecs list-clusters --query 'clusterArns[]' --output text); do
  for t in $(aws ecs list-tasks --cluster "$c" --query 'taskArns[]' --output text); do
    eni=$(aws ecs describe-tasks --cluster "$c" --tasks "$t" \
      --query 'tasks[].attachments[].details[?name==`networkInterfaceId`].value' --output text)
    aws ec2 describe-network-interfaces --network-interface-ids "$eni" \
      --query 'NetworkInterfaces[].Association.PublicIp' --output text
  done
done
```

**Gotcha**: a task exposing an app port directly (no ALB in front) skips ALB-layer WAF and logging — correlate the account's Fargate/EC2 IP ranges (base-file attribution) with a `naabu` sweep to find these.

### EKS Ingress

**Pattern**: ALB Ingress (AWS Load Balancer Controller) → `https://<name>-<hash>.<region>.elb.amazonaws.com` (internet-facing ALB); NLB (Service `type: LoadBalancer`) → `<name>-<hash>.elb.<region>.amazonaws.com` (note the differing label order) — raw TCP, so non-HTTP services can sit here directly.

```bash
aws elbv2 describe-load-balancers --query 'LoadBalancers[].{dns:DNSName,scheme:Scheme,type:Type}'
# from a leaked kubeconfig:
kubectl get ingress,svc -A -o wide | grep -iE 'elb|amazonaws'
```

**Confirm**: the ELB DNS appears in CT only if a custom domain with an ACM cert is attached; otherwise mine it from the app or `kubectl`. Correlate to the target by ACM cert SAN or account IP range.

**Gotcha**: `internet-facing` scheme ALBs are the external edge; `internal` scheme ones are chain targets. Load `kubernetes` once you hold a kubeconfig — this is edge discovery only.

### Global Accelerator

**Pattern**: `https://<hex>.awsglobalaccelerator.com` with two static anycast IPs fronting the accelerator; the backend can be an ALB/NLB/EC2/EIP across regions.

```bash
aws globalaccelerator list-accelerators --region us-west-2 \
  --query 'Accelerators[].{name:Name,dns:DnsName,ips:IpSets[].IpAddresses}'
grep -rhoE '[a-z0-9]+\.awsglobalaccelerator\.com' bundles/ | sort -u
```

**Gotcha**: the two anycast IPs are stable and often the only externally-visible edge — the backend endpoints and their regions hide behind them; enumerate accelerators from the account (the API is global, pinned to `us-west-2`) to reveal the backend map.

### Elastic Beanstalk

**Pattern**: `http://<env>.<region>.elasticbeanstalk.com` (legacy: `<env>.elasticbeanstalk.com`, no region). The environment sits behind an ELB or a single instance; the CNAME is often reused as the app's public host.

```bash
grep -rhoE '[a-z0-9-]+\.([a-z0-9-]+\.)?elasticbeanstalk\.com' bundles/ | sort -u
aws elasticbeanstalk describe-environments \
  --query 'Environments[].{env:EnvironmentName,cname:CNAME,url:EndpointURL,status:Status}'
```

**Gotcha**: the `EndpointURL` is often the raw ELB DNS (no WAF) while the `CNAME` may be fronted differently — test both. Environments left in `Terminated` state with DNS still live serve stale code.

### AppSync (GraphQL)

**Pattern**: HTTP `https://<api-id>.appsync-api.<region>.amazonaws.com/graphql`; realtime `wss://<api-id>.appsync-realtime-api.<region>.amazonaws.com/graphql` (verified 2026-09). Auth via `x-api-key`, Cognito/OIDC JWT, or IAM SigV4.

```bash
grep -rhoE '[a-z0-9]+\.appsync-(realtime-)?api\.[a-z0-9-]+\.amazonaws\.com' bundles/ | sort -u
curl -s https://<api-id>.appsync-api.<region>.amazonaws.com/graphql \
  -H 'x-api-key: <key>' -H 'content-type: application/json' \
  -d '{"query":"{__schema{types{name}}}"}'
```

**Confirm**: a JSON `data.__schema` response means introspection is open. Load `graphql` for depth/batching/authorization abuse; this is endpoint + key discovery.

**Gotcha**: the `x-api-key` is frequently hardcoded in the client bundle — mine it alongside the endpoint. API-key auth has no per-user scoping.

### Cognito

**Pattern**: hosted UI `https://<domain-prefix>.auth.<region>.amazoncognito.com`; user-pool API `https://cognito-idp.<region>.amazonaws.com`; identity-pool API `https://cognito-identity.<region>.amazonaws.com`.

```bash
grep -rhoE '(cognito-idp|cognito-identity)\.[a-z0-9-]+\.amazonaws\.com|[a-z0-9-]+\.auth\.[a-z0-9-]+\.amazoncognito\.com' bundles/ | sort -u
# bundles leak the user-pool id (<region>_XXXXXXXXX), app-client id, and often an identity-pool id (<region>:<uuid>)
grep -rhoE '[a-z]{2}-[a-z]+-[0-9]+_[A-Za-z0-9]{9}|[a-z]{2}-[a-z]+-[0-9]+:[0-9a-f-]{36}' bundles/ | sort -u
```

**Confirm**: an identity-pool that allows unauthenticated identities hands real (if scoped) AWS credentials to anyone with the pool id — the classic Cognito finding. Load `aws` and `authentication_jwt` for exploitation.

**Gotcha**: the user-pool id and app-client id are public by design — the finding is unauthenticated identity-pool credentials or self-signup granting elevated groups, not the ids themselves.

### Lightsail

**Pattern**: container service `https://<name>.<hash>.<region>.cs.amazonlightsail.com`; instances get raw static IPs. Lightsail is a separate, often-forgotten control plane on the same account.

```bash
aws lightsail get-container-services --query 'containerServices[].{name:containerServiceName,url:url}'
grep -rhoE '[a-z0-9-]+\.[a-z0-9]+\.[a-z0-9-]+\.cs\.amazonlightsail\.com' bundles/ | sort -u
```

**Gotcha**: Lightsail firewalls default open on common ports; a Lightsail instance is a cheap-to-forget host running production side-projects outside the main VPC's controls.

## Azure Runtime Surface

Azure runtime FQDNs embed a region and, for newer services, an environment identifier. Enumerate per region and per subscription — a target's non-prod subscription often shares naming. Credentialed sweep:

```bash
az account list --query '[].{name:name,id:id}' -o table
az webapp list --query '[].defaultHostName' -o tsv
az functionapp list --query '[].defaultHostName' -o tsv
az containerapp list --query '[].properties.configuration.ingress.fqdn' -o tsv
az staticwebapp list --query '[].defaultHostname' -o tsv
```

### App Service and Function Apps

**Pattern**: `https://<app>.azurewebsites.net` (Function Apps share the domain). `<app>` is globally unique — a released name can be re-registered by an attacker (subdomain-takeover lead; hand to `subdomain_takeover`).

```bash
grep -rhoE '[a-z0-9-]+\.(scm\.)?azurewebsites\.net' bundles/ | sort -u
# deployment slots (pre-release code, looser auth)
for s in staging dev test preview canary blue green; do
  echo "$s $(curl -s -o /dev/null -w '%{http_code}' https://<app>-$s.azurewebsites.net)"; done
curl -sI https://<app>.azurewebsites.net | grep -iE 'x-azure|x-aspnet|server'
```

**Confirm**: `x-azure-ref` and often `x-aspnet-version`/`x-powered-by: ASP.NET`. The **SCM/Kudu** site `https://<app>.scm.azurewebsites.net` is the deployment/console surface — weak auth or a leaked publishing profile here is code execution.

**Gotcha**: Consumption-plan Function Apps cold-start — a first request after idle takes seconds, a warm one is fast; timing first-vs-second request distinguishes plan tier (shared vs dedicated infra).

### Azure Static Web Apps

**Pattern**: `https://<name>.azurestaticapps.net` (sometimes region-suffixed `<name>.<region-code>.azurestaticapps.net`). Ships a managed Functions API at `/api/*` on the same origin.

```bash
curl -s https://<name>.azurestaticapps.net/api/ -o /dev/null -w '%{http_code}\n'
# PR/branch preview environments (less-hardened)
curl -sI 'https://<name>-<env>.<region>.azurestaticapps.net'
```

**Gotcha**: preview environments per PR/branch use dev config; mine `staticwebapp.config.json` route rules from the repo if source is available.

### Azure Container Apps

**Pattern** (verified 2026-09): `https://<app>.<env-unique-id>.<region>.azurecontainerapps.io`, e.g. `myapp.happyhill-70162bb9.canadacentral.azurecontainerapps.io`. The `<env-unique-id>` (word + hex) is per Container Apps **environment** and shared by every app in it — one app's FQDN gives you the environment id to enumerate siblings.

```bash
grep -rhoE '[a-z0-9-]+\.[a-z0-9-]+\.[a-z0-9-]+\.azurecontainerapps\.io' bundles/ | sort -u
az containerapp env list --query '[].{name:name,domain:properties.defaultDomain}' -o table
az containerapp list --query '[].{app:name,fqdn:properties.configuration.ingress.fqdn,ext:properties.configuration.ingress.external}' -o table
```

**Confirm**: an internal-ingress app carries an `.internal.` segment: `<app>---<label>.internal.<env-id>.<region>.azurecontainerapps.io` — reachable only from inside the environment (SSRF-chain target). Revision labels use a triple-dash `<app>---<label>.<env-id>...`.

**Gotcha**: old labelled revisions often stay live and serve pinned (vulnerable) code — enumerate labels, not just the base app FQDN.

### Azure Container Instances

**Pattern**: `https://<name>.<region>.azurecontainer.io` when a DNS name label is set; otherwise a raw public IP. ACI has no built-in WAF/ingress — the container port is exposed directly.

```bash
az container list --query '[].{name:name,fqdn:ipAddress.fqdn,ip:ipAddress.ip,ports:ipAddress.ports}' -o table
naabu -host <name>.<region>.azurecontainer.io -top-ports 100
```

**Gotcha**: the DNS label is globally unique per region — a resolving `<name>.<region>.azurecontainer.io` confirms the container exists; port-sweep the IP for the exposed service.

### AKS Ingress

**Pattern**: NGINX Ingress → Azure public IP with hostnames from ingress rules; Application Gateway Ingress Controller (AGIC) → App Gateway frontend with `<name>.<region>.cloudapp.azure.com` default DNS and (WAF_v2 SKU) a WAF.

```bash
az network public-ip list --query '[].{ip:ipAddress,dns:dnsSettings.fqdn}' -o table
kubectl get ingress -A -o wide     # from a leaked kubeconfig
```

**Gotcha**: when Azure Front Door fronts AKS, the origin ingress may be locked to the `AzureFrontDoor.Backend` service tag — test whether the origin IP answers directly (Front-Door-bypass) to reach it without the WAF.

### Azure Front Door and CDN

**Pattern**: `https://<name>.azurefd.net` (Front Door Standard/Premium) or `<name>.azureedge.net` (classic CDN, retiring). Front Door is a reverse proxy — the target is the **origin behind it**.

```bash
az afd profile list --query '[].name' -o tsv
az afd origin list --profile-name <p> --origin-group-name <g> --resource-group <rg> \
  --query '[].{host:hostName,enabled:enabledState}' -o table
```

**Gotcha**: a common misconfiguration is an origin that accepts traffic from any source, not only the Front Door service tag — resolve the origin host and test direct reachability to bypass the Front Door WAF.

### Azure API Management

**Pattern**: `https://<name>.azure-api.net` (gateway); also `<name>.developer.azure-api.net` and the **developer portal**. A public portal lists every published API, operations, and schemas.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<name>.developer.azure-api.net
az apim list --query '[].{name:name,gw:gatewayUrl,portal:developerPortalUrl}' -o table
```

**Gotcha**: check for self-service product subscriptions (open API-key signup) that grant backend access without approval.

### App Service Environment (ASE)

**Pattern** (verified 2026-09): an internal/ILB ASEv3 serves apps at `https://<app>.<ase-name>.appserviceenvironment.net`, SCM at `<app>.scm.<ase-name>.appserviceenvironment.net`; a `*.<ase-name>.appserviceenvironment.net` zone points at the ASE inbound (internal) VIP. External ASE apps still use `.azurewebsites.net`.

```bash
grep -rhoE '[a-z0-9-]+\.[a-z0-9-]+\.appserviceenvironment\.net' bundles/ | sort -u
az appservice ase list --query '[].{name:name,kind:kind}' -o table
```

**Gotcha**: ILB ASE apps resolve only inside the target VNet — reachable from a foothold, not externally; catalog as internal chain targets. An `.appserviceenvironment.net` name leaking in a bundle confirms an internal ASE exists.

### Logic Apps

**Pattern**: a Consumption Logic App HTTP-trigger callback URL embeds a SAS signature: `https://<region>.logic.azure.com:443/workflows/<wf-id>/triggers/manual/paths/invoke?...&sig=<sig>`. The `sig` is a bearer capability — anyone with the URL fires the workflow.

```bash
grep -rhoE 'https://[a-z0-9-]+\.logic\.azure\.com[^ "]*sig=[^ "&]+' bundles/ | sort -u
```

**Gotcha**: these callback URLs leak in client code, email, and CI logs; a leaked one invokes the workflow (which may write data, send mail, or call internal systems) with no Azure identity. Validate the `sig` before assuming it rotated.

### SignalR Service

**Pattern**: `https://<name>.service.signalr.net`. The `/client/negotiate` (and hub `/negotiate`) endpoints issue a connection token.

```bash
grep -rhoE '[a-z0-9-]+\.service\.signalr\.net' bundles/ | sort -u
curl -s -o /dev/null -w '%{http_code}\n' 'https://<name>.service.signalr.net/client/negotiate?hub=<hub>'
```

**Gotcha**: a `negotiate` that returns a token to an unauthenticated client is a real-time-channel takeover — subscribe and read broadcast messages (hand message abuse to the app-layer skill).

## GCP Runtime Surface

GCP runtime URLs are the most **predictable** of the three clouds — App Engine and the new Cloud Run deterministic form are guessable from project + service names, so enumeration is often prediction, not discovery. Credentialed sweep:

```bash
gcloud run services list --format='value(status.url)'
gcloud functions list --format='value(name,httpsTrigger.url)'
gcloud app services list 2>/dev/null
```

### Cloud Run Services

Two URL forms coexist (verified 2026-09):
- **Deterministic (GA, predictable)**: `https://<service>-<project-number>.<region>.run.app` — e.g. `api-123456789012.us-central1.run.app`. Guessable: service name + numeric project number + region construct the URL before it is public. Project numbers leak in error messages, JS config, and OIDC discovery. Only assigned when the label (`<service>-<project-number>`) is ≤63 chars.
- **Legacy hash**: `https://<service>-<hash>-<regioncode>.a.run.app` — e.g. `api-abc123xyz-uc.a.run.app` (`uc`=us-central1). The hash is not guessable; source-mine it.

```bash
grep -rhoE 'https://([a-z0-9-]+\.)+run\.app' bundles/ | sort -u
# construct deterministic URLs once project number + services are known
for svc in api web auth admin worker; do
  echo "https://$svc-<project-number>.us-central1.run.app"; done
curl -sI https://<service>-<project-number>.us-central1.run.app | grep -iE 'server|x-cloud-trace'
```

**Confirm**: `server: Google Frontend` + `x-cloud-trace-context`. A `403` with a Google IAM sign-in page = auth required; an app response = `--allow-unauthenticated`. Traffic tags prepend `<tag>---` and route to a specific (possibly old, pinned) revision.

**Gotcha**: Cloud Run functions gen2 deploy as Cloud Run — a `run.app` host may be a "function"; don't assume `cloudfunctions.net` covers gen2.

### Cloud Functions (gen1)

**Pattern**: `https://<region>-<project-id>.cloudfunctions.net/<function>` — predictable from project id + region + function name (uses the **project id** string, not the number).

```bash
grep -rhoE '[a-z0-9-]+-[a-z0-9-]+\.cloudfunctions\.net/[a-zA-Z0-9_-]+' bundles/ | sort -u
for fn in api webhook auth stripe handler main callback; do
  echo "$fn $(curl -s -o /dev/null -w '%{http_code}' https://<region>-<project-id>.cloudfunctions.net/$fn)"; done
```

**Gotcha**: a `403` may mean the function exists but requires auth; a `404` means no such function — the distinction confirms existence.

### Cloud Functions (gen2)

Deploys on Cloud Run infrastructure — the invocation URL is a Cloud Run `run.app` URL (above), not `cloudfunctions.net`. Check both surfaces; gen2 is increasingly the default.

### App Engine

Fully predictable from the project id:
- Default service: `https://<project-id>.appspot.com` (newer apps also `<project-id>.<region>.r.appspot.com`)
- Named service: `https://<service>-dot-<project-id>.appspot.com`
- Specific version: `https://<version>-dot-<service>-dot-<project-id>.appspot.com`

```bash
gcloud app services list --format='value(id)'
gcloud app versions list --format='value(service,id,traffic_split)'
for s in default api admin worker; do
  echo "$s $(curl -s -o /dev/null -w '%{http_code}' https://$s-dot-<project-id>.appspot.com)"; done
```

**Gotcha**: **version-pinned URLs serve old code** — enumerate versions (mined from repos, or the auto-version `YYYYMMDDtHHMMSS` format) to reach a patched-in-prod-but-still-deployed vulnerable version. This is a prime rollback-to-vulnerable path.

### GKE Ingress

**Pattern**: GCLB (Google Cloud Load Balancer) global anycast IP; hostnames from `Ingress`/`Gateway` objects and their managed certs.

```bash
gcloud compute forwarding-rules list --format='value(name,IPAddress,target)'
gcloud compute ssl-certificates list --format='value(name,managed.domains)'
```

**Gotcha**: mine the managed certificate SANs (custom domains) via CT; the internal `<hash>.<region>.gke.goog`-style names are not public. Autopilot vs Standard changes post-foothold blast radius (load `kubernetes`).

### Firebase Hosting

**Pattern**: canonical `https://<project-id>.web.app`; legacy alias `https://<project-id>.firebaseapp.com` (both usually serve the same site).

```bash
# firebaseConfig in the client bundle reveals project id + additional sites
grep -rhoE '"(projectId|authDomain|storageBucket)":\s*"[^"]+"' bundles/ | sort -u
curl -s -o /dev/null -w '%{http_code}\n' https://<project-id>.web.app
```

**Confirm**: **preview channels** (verified 2026-09): `https://<project-id>--<channel-id>-<random-hash>.web.app`, e.g. `myproj--pr-42-a1b2c3d4.web.app` — public but hash-guarded, default 7-day expiry. Mine channel URLs from CI logs and PR comments, not by guessing.

**Gotcha**: multi-site projects use `<site-id>.web.app` where `<site-id>` differs from the project id — enumerate additional sites from the bundle's `firebaseConfig`.

### Firebase Functions

HTTP-triggered functions surface as Cloud Functions/Cloud Run URLs (above). **Callable functions** are POST endpoints under the functions URL invoked with a `{"data": ...}` envelope and a Firebase-Auth bearer token.

```bash
grep -rhoE "httpsCallable\(['\"][a-zA-Z0-9_-]+['\"]\)" bundles/ | sort -u
```

**Gotcha**: enumerate callable names from `httpsCallable('<name>')` in the bundle; load `firebase` for the auth/rules exploitation — this is endpoint discovery only.

### Apigee

**Pattern**: Apigee Edge SaaS `https://<org>-<env>.apigee.net` (e.g. `acme-prod.apigee.net`, `acme-test.apigee.net`); Apigee X uses custom domains, but eval/legacy orgs still surface on `.apigee.net`.

```bash
grep -rhoE '[a-z0-9-]+-[a-z0-9-]+\.apigee\.net' bundles/ | sort -u
for e in prod test dev staging; do
  echo "$e $(curl -s -o /dev/null -w '%{http_code}' https://<org>-$e.apigee.net/)"; done
```

**Gotcha**: the `<env>` segment (`test`/`dev`) exposes non-prod API proxies with looser policies on the same org — enumerate environments, not just prod.

### Identity Platform / Firebase Auth

**Pattern**: GCP Identity Platform reuses the Firebase Auth surface — `https://identitytoolkit.googleapis.com/v1/accounts:*?key=<api-key>` and the `<project>.firebaseapp.com/__/auth/` handler. The `apiKey` (`AIza...`) is public by design.

```bash
grep -rhoE '"apiKey":\s*"AIza[0-9A-Za-z_-]{35}"' bundles/ | sort -u
```

**Gotcha**: the finding is unauthenticated `accounts:signUp` / `signInWithPassword` / email-enumeration against the Identity Toolkit, not the key itself — load `firebase` for the REST-abuse workflow.

## Storage Surface

Storage endpoints are the highest-frequency cloud finding — public buckets, over-shared blobs, world-readable datasets. Enumerate per provider with tenancy-aware tooling.

### AWS Storage

S3 has several equivalent host forms — test all; WAF/logging often differs by form:
- `https://<bucket>.s3.<region>.amazonaws.com` (virtual-hosted, regional — canonical)
- `https://s3.<region>.amazonaws.com/<bucket>` (path-style — deprecating, still served)
- `https://<bucket>.s3.amazonaws.com` (legacy global)
- `https://<bucket>.s3-website-<region>.amazonaws.com` (static website — no HTTPS, different auth, serves even when the REST endpoint is private)
- `https://<bucket>.s3.dualstack.<region>.amazonaws.com` (IPv6)

```bash
# credentialed
aws s3api list-buckets --query 'Buckets[].Name'
# name mutation + public check
for n in <org>-assets <org>-backups <org>-logs <org>-prod <org>-terraform-state; do
  curl -s -o /dev/null -w "%{http_code} $n\n" "https://$n.s3.amazonaws.com/"; done
s3-account-search <bucket>          # attribute a bucket to a known account id
```

**Confirm**: `403` = bucket exists, no anon access; `404 NoSuchBucket` = free/nonexistent; `200` with `<ListBucketResult>` = anonymous list. Tools: `s3-account-search` (account attribution), `s3-inspector`/`bucketsloth` (ACL+policy), `AWSBucketDump` (wordlist enum + download).

**Gotcha**: CloudFront `https://d<hash>.cloudfront.net` fronts many buckets; a distribution that accepts direct origin traffic (no `Referer`/custom-header origin lock) is a WAF bypass. EFS/FSx are VPC-internal — `aws efs describe-file-systems` from a foothold only.

### Azure Storage

One account exposes multiple service endpoints — enumerate all five plus Cosmos:
- Blob `https://<account>.blob.core.windows.net`, ADLS Gen2 `.dfs.core.windows.net`, File `.file.core.windows.net`, Table `.table.core.windows.net`, Queue `.queue.core.windows.net`

```bash
# account names are global; resolving on any service host confirms existence
for svc in blob dfs file table queue; do
  host=<account>.$svc.core.windows.net
  echo "$svc $(dig +short $host | head -1)"; done
# anonymous container list
curl -s 'https://<account>.blob.core.windows.net/<container>?restype=container&comp=list'
```

**Confirm**: a `200` with `<EnumerationResults>` is anonymous list access. A leaked SAS URL (`?sv=...&sig=...`) is a bearer credential — validate its signed permissions/expiry, don't assume expired.

**Gotcha**: Cosmos DB endpoints reveal the data model by suffix: `<account>.documents.azure.com` (SQL/core), `.mongo.cosmos.azure.com`, `.cassandra.cosmos.azure.com`, `.table.cosmos.azure.com`, `.gremlin.cosmos.azure.com` — a leaked connection string/key is full data-plane access.

### GCP Storage

**Pattern**: `https://storage.googleapis.com/<bucket>`, `https://<bucket>.storage.googleapis.com`, JSON API `https://storage.googleapis.com/storage/v1/b/<bucket>/o`.

```bash
gcpbucketbrute -k <keyword> -u            # unauth ACL enumeration
curl -s 'https://storage.googleapis.com/storage/v1/b/<bucket>/o' -o /dev/null -w '%{http_code}\n'
gcloud storage buckets list 2>/dev/null   # credentialed
```

**Confirm**: `gcpbucketbrute` reports `allUsers`/`allAuthenticatedUsers` (public) ACLs without credentials; a `200` object listing on the JSON API is anonymous read. Predefined ACLs to watch: `publicRead`, `publicReadWrite` (world-writable, critical).

**Gotcha**: BigQuery datasets can be shared `allAuthenticatedUsers`/`allUsers` — `bq ls --project_id=<id>` (any Google auth) surfaces leaked internal datasets.

## Edge Platforms

Edge/JAMstack platforms deploy from git, so **preview deployments per branch/PR are ubiquitous and under-hardened** — dev secrets, auth added later, never deleted. Every platform wildcard-fronts its default subdomain (no CT for the default subdomain), so source-mine the bundle and mine the org's public git for branch names. A leaked platform token enumerates the whole account — check for token exposure first.

### Cloudflare Workers

**Pattern**: `https://<script>.<subdomain>.workers.dev` — `<subdomain>` is the account's one workers.dev subdomain, `<script>` the Worker name.

```bash
grep -rhoE '[a-z0-9-]+\.[a-z0-9-]+\.workers\.dev' bundles/ | sort -u
# credentialed (leaked CF token)
wrangler deployments list 2>/dev/null
curl -s -H "Authorization: Bearer $CF_TOKEN" \
  "https://api.cloudflare.com/client/v4/accounts/$ACCT/workers/scripts" | jq -r '.result[].id'
wrangler kv namespace list; wrangler r2 bucket list; wrangler d1 list
```

**Confirm**: knowing the account `<subdomain>` lets you enumerate script names. Bound resources reachable from a Worker (each a chain target): KV namespaces, R2 buckets (also `https://<hash>.r2.cloudflarestorage.com`), D1 databases, Durable Objects, Queues.

**Gotcha**: Workers Routes bind a Worker to a custom domain/path (`example.com/api/*`) — those show in CT (custom domain); correlate to the account.

### Cloudflare Pages

**Pattern**: `https://<project>.pages.dev` (production); deploy previews `https://<hash>.<project>.pages.dev`; branch aliases `https://<branch>.<project>.pages.dev` (guessable from org branch names).

```bash
grep -rhoE '[a-z0-9-]+\.pages\.dev' bundles/ | sort -u
for b in main develop staging preview test; do
  echo "$b $(curl -s -o /dev/null -w '%{http_code}' https://$b.<project>.pages.dev)"; done
```

**Gotcha**: Pages Functions surface at `/functions/*`-derived routes; mine `_worker.js`/`functions/` from the repo if source is available.

### Vercel

**Pattern**: production `https://<project>.vercel.app`; preview (verified 2026-09) `https://<project>-git-<branch>-<scope>.vercel.app` (the `-git-<branch>` infix is the tell) and per-deploy `https://<project>-<random>-<scope>.vercel.app`, `<scope>` = team/user slug.

```bash
grep -rhoE '[a-z0-9-]+(-git-[a-z0-9-]+)?(-[a-z0-9]+)?\.vercel\.app' bundles/ | sort -u
vercel projects ls 2>/dev/null       # leaked Vercel token
curl -s -H "Authorization: Bearer $VERCEL_TOKEN" 'https://api.vercel.com/v6/deployments' | jq -r '.deployments[].url'
```

**Confirm**: `server: Vercel` + `x-vercel-id`. Surface conventions: Serverless Functions `/api/*`, Edge Middleware (`x-middleware-*`, rewrites), Next.js `/_next/*` (mine `_buildManifest.js` per `application_enumeration`).

**Gotcha**: labels are truncated to the 63-char DNS limit and shortened by anti-phishing, so the on-wire host may be shorter than constructed — match on the stable `<project>` prefix.

### Netlify

**Pattern**: `https://<site>.netlify.app`; deploy previews `https://deploy-preview-<pr>--<site>.netlify.app` (per PR) and `https://<branch>--<site>.netlify.app` (branch deploys) — `--` double-dash, guessable given PR numbers.

```bash
grep -rhoE '[a-z0-9-]+(--[a-z0-9-]+)?\.netlify\.app' bundles/ | sort -u
netlify sites:list 2>/dev/null; netlify functions:list 2>/dev/null
```

**Confirm**: `server: Netlify`. Function paths: `/.netlify/functions/<name>` (Lambda), `/.netlify/edge-functions/<name>` (Deno edge), `/.netlify/builders/<name>` (on-demand) — enumerate names from the bundle and the repo's `netlify/functions/` dir.

**Gotcha**: deploy-preview URLs frequently outlive the closed PR and serve dev config — mine every open and closed PR.

### Deno Deploy

**Pattern**: `https://<project>.deno.dev`; per-PR/branch preview `https://<project>-<deploy-id>.deno.dev`. Runs at the edge — source-mine the project name; the dashboard/API enumerate deployments when a token leaks.

```bash
grep -rhoE '[a-z0-9-]+(-[a-z0-9]+)?\.deno\.dev' bundles/ | sort -u
deployctl deployments list --project=<project> 2>/dev/null   # leaked Deno Deploy token
```

**Gotcha**: per-deploy `<project>-<deploy-id>.deno.dev` URLs are immutable and stay public after a rollback — an old deploy id mined from CI still serves the vulnerable build.

### Fly.io

**Pattern**: `https://<app>.fly.dev` (anycast to nearest region). Per-machine/region internal names (`<region>.<app>.internal`, `<alloc-id>.vm.<app>.internal`) are reachable inside the Fly 6PN WireGuard mesh — SSRF/foothold targets.

```bash
grep -rhoE '[a-z0-9-]+\.fly\.dev' bundles/ | sort -u
fly apps list 2>/dev/null; fly status -a <app>; fly machine list -a <app>
```

**Gotcha**: the `.internal` names only resolve inside the Fly private network — catalog as internal chain targets once you have a foothold in a Fly machine.

### Railway

**Pattern**: `https://<project>.up.railway.app` (also `<service>-<project>.up.railway.app`). Custom domains bind via CNAME (in CT). PR environments each get a URL — the under-hardened ones.

```bash
grep -rhoE '[a-z0-9-]+\.up\.railway\.app' bundles/ | sort -u
```

**Gotcha**: Railway private networking exposes `<service>.railway.internal` names reachable only between services in the project — internal chain targets from a foothold, and a service with no public domain is internal-only by design.

### Render

**Pattern**: `https://<service>.onrender.com`; PR previews `https://<service>-pr-<n>.onrender.com`.

```bash
grep -rhoE '[a-z0-9-]+(-pr-[0-9]+)?\.onrender\.com' bundles/ | sort -u
curl -s -H "Authorization: Bearer $RENDER_TOKEN" https://api.render.com/v1/services | jq -r '.[].service.serviceDetails.url' 2>/dev/null
```

**Gotcha**: Render "private services" have no public URL — they are internal chain targets; a "web service" is public. Static sites, web services, and private services differ in exposure.

### Bun runtime (not a hosting platform)

Bun is a **runtime**, not a hosting platform — there is no `*.bun.sh` deployment URL. Bun apps deploy onto the platforms above (Railway/Render/Fly/Vercel) and take those platforms' URLs. Detect Bun as the runtime, not a distinct surface: a `Server: Bun` header, Bun-specific error pages, or `Bun.serve` behavior. It matters only because Bun's HTTP parsing and default routing differ from Node — a hunter hint, not a new host class. (Verified 2026-09: Bun ships no first-party hosting product with its own subdomain.)

### GitHub Pages

**Pattern**: `https://<user-or-org>.github.io` (user/org site) and `https://<user-or-org>.github.io/<repo>/` (project site). Custom domains bind via CNAME (in CT). The backing repo is public by definition.

```bash
grep -rhoE '[a-z0-9-]+\.github\.io[^ "]*' bundles/ | sort -u
```

**Gotcha**: a custom-domain Pages site whose repo/org was deleted or renamed is a subdomain-takeover lead (hand to `subdomain_takeover`); and the backing repo usually holds the full source + history — mine it for secrets and endpoints.

### Cloudflare Access (Zero Trust)

**Pattern**: `https://<team-name>.cloudflareaccess.com` — the org's Access team domain; protected apps sit behind it and set a `CF_Authorization` JWT cookie. The app launcher at `/` may list protected apps.

```bash
grep -rhoE '[a-z0-9-]+\.cloudflareaccess\.com' bundles/ | sort -u
curl -sI https://<app>.<domain>/ | grep -iE 'cf-access|location.*cloudflareaccess'
```

**Gotcha**: a `302` to `<team>.cloudflareaccess.com` marks an Access-protected app — the bypass targets are Access misconfiguration (open policy, leaked service token) and any origin reachable without the Access JWT (origin not locked to Cloudflare IP ranges).

### Koyeb

**Pattern** (verified 2026-09): `https://<app>-<org>.koyeb.app`; custom domains via CNAME.

```bash
grep -rhoE '[a-z0-9-]+-[a-z0-9-]+\.koyeb\.app' bundles/ | sort -u
```

**Gotcha**: Koyeb service discovery uses internal `<service>.<app>.internal` names — internal chain targets from a foothold, not external hosts.

## Cross-Tenant Identity Federation Surface

Federation trust is the most-forgotten cloud surface — a trust set up years ago for a since-departed partner still lets an external identity assume internal roles. Enumerate the trust graph, not just the hosts.

- **IAM Identity Center (AWS SSO)**: portal `https://<subdomain>.awsapps.com/start` (`<subdomain>` org-chosen, guessable/mined). Credentialed: `aws sso-admin list-instances`, `aws sso-admin list-permission-sets --instance-arn <arn>`, `list-accounts-for-provisioned-permission-set` — over-broad permission sets assigned across many accounts are the finding.
- **Entra External ID / B2B**: `curl -s https://login.microsoftonline.com/<domain>/.well-known/openid-configuration` reveals the tenant id (public); enumerate invited/partner domains and whether cross-tenant access policy allows inbound B2B from an attacker-controllable tenant. Guest accounts often retain more directory read than expected (`roadrecon gather` with a guest token).
- **GCP Workload Identity Federation**: `gcloud iam workload-identity-pools list --location global` and `...providers describe` reveal the trusted issuer, allowed audiences, and `attribute-condition`. A missing/wildcard `attribute-condition` on `sub`/`aud` lets the wrong external identity mint SA tokens.
- **Kubernetes ServiceAccount OIDC federation** (EKS IRSA, GKE WI, AKS workload identity): the cluster OIDC issuer (`https://oidc.eks.<region>.amazonaws.com/id/<hash>`) is often public; the trust `sub` condition (`system:serviceaccount:<ns>:<sa>`) is the target — an over-broad/`StringLike`-wildcard `sub` lets any pod assume the cloud role.
- **OIDC trust-policy inspection**: for any federated role, read the JWT `aud` and `sub` conditions. Trust checking only `aud` (not `sub`), or a wildcard, is assumable by an unintended identity.
- **Cross-account IAM role assumption**: enumerate roles trusting external account roots (`arn:aws:iam::<acct>:root`) — missing `sts:ExternalId` or `aws:SourceArn` is the confused-deputy lead (load `aws`).
- **AWS Access Analyzer**: `aws accessanalyzer list-findings` (with read) surfaces every resource shared outside the account/org — a pre-computed external-exposure list.

**Federation enumeration** (read access where noted; unauthenticated where marked):

```bash
# AWS SSO / Identity Center + cross-account trust + external exposure
aws sso-admin list-instances
aws sso-admin list-permission-sets --instance-arn <arn>
aws iam list-roles --query 'Roles[?AssumeRolePolicyDocument].{r:RoleName,trust:AssumeRolePolicyDocument}' --output json
aws accessanalyzer list-analyzers && aws accessanalyzer list-findings --analyzer-arn <arn>
# GCP workload identity federation trust (issuer + attribute-condition)
gcloud iam workload-identity-pools list --location global --format='value(name)'
gcloud iam workload-identity-pools providers describe <prov> --location global --workload-identity-pool <pool>
# Entra tenant id from a domain (unauthenticated) and the cluster OIDC issuer
curl -s https://login.microsoftonline.com/<domain>/.well-known/openid-configuration | jq -r .issuer
curl -sk https://<kube-api>:6443/.well-known/openid-configuration | jq -r .issuer
```

## Ephemeral and Runtime Compute

Ephemeral compute has a short-lived but recurring public surface — CI runners, cloud IDEs, PR previews. Catalog the ranges and patterns; the previews especially are under-hardened.

- **GitHub Actions runner ranges**: `curl -s https://api.github.com/meta | jq -r '.actions[]'` lists hosted-runner egress ranges; mine the target's public workflow logs for the IPs/regions its self-hosted runners use (self-hosted runners on the target VPC are a foothold).
- **CI/CD egress ranges**: CircleCI, Travis, Jenkins-cloud publish IP ranges — a webhook/allowlist keyed to a shared CI range trusts every tenant on that CI.
- **GitHub Codespaces port forwarding**: `https://<name>-<port>.app.github.dev` — a forwarded port set to public visibility is an internet-exposed dev service; `<name>` is the codespace slug. Mine from developer chatter/docs.
- **Gitpod / StackBlitz**: Gitpod `https://<port>-<workspace>.<cluster>.gitpod.io`; StackBlitz WebContainers run in-browser but the `*.webcontainer.io` preview proxy can expose a dev server.
- **PR preview environments** (Vercel/Netlify/Render/Railway/Amplify): the single highest-value ephemeral surface — mine open and closed PRs for preview URLs that outlive the PR and serve dev config.
- **Cloud IDE / agent workspaces** (2025-era): browser-hosted dev/agent environments forward ports like Codespaces; treat any `*.app.github.dev`-style forwarded port as a candidate live service.

**Ephemeral surface commands**:

```bash
# GitHub hosted-runner egress ranges + Actions/Dependabot domains
curl -s https://api.github.com/meta | jq -r '.actions[], .dependabot[]?'
# the org's public workflow runs (mine logs/artifacts for preview URLs and forwarded ports)
gh api "/repos/<org>/<repo>/actions/runs?per_page=100" --jq '.workflow_runs[].html_url' 2>/dev/null
# probe a discovered Codespaces forwarded port (public visibility = internet-exposed dev service)
curl -s -o /dev/null -w '%{http_code}\n' https://<name>-<port>.app.github.dev/
```

## Container Ingress Discovery

Service-mesh and ingress control planes ship admin/diagnostic surfaces frequently exposed by accident on internal (sometimes external) LoadBalancers. Probe for these whenever a Kubernetes-native target is in scope.

```bash
# probe a reachable ingress/mesh host for exposed control-plane surfaces
for p in "15000/config_dump" "15000/clusters" "8001/" "8080/dashboard/" "8080/api/rawdata" \
         "8877/ambassador/v0/diag/" "6443/api/v1/namespaces" "6443/version"; do
  echo "$p $(curl -sk -o /dev/null -w '%{http_code}' https://<host>:${p%%/*}/${p#*/})"; done
```

- **Envoy admin** (`:15000`): `/config_dump` (routes + SDS secret refs), `/clusters`, `/stats`, `/certs`, `/server_info`. In an Istio mesh this is the `istio-proxy` sidecar's localhost admin — reachable from any container sharing the pod netns, occasionally bound externally.
- **Istio ingress gateway**: the `istio-ingressgateway` LoadBalancer is the mesh edge; **Kiali** and **Jaeger** UIs are often deployed alongside and exposed — both leak the full service graph and traces.
- **Linkerd**: `linkerd-viz` dashboard (legacy `linkerd-web`) expose topology and live traffic.
- **Cilium**: the **Hubble UI** exposes flow-level observability; correlate a `LoadBalancer` Service to a Cilium ingress.
- **Traefik**: `/dashboard/` (trailing slash required) and `/api/rawdata` — the API dumps every router, service, and middleware including backend URLs.
- **Ambassador / Emissary**: `/ambassador/v0/diag/` — full mapping/route config.
- **Kong Admin API** (`:8001`, or `:8444` TLS): if exposed, lists and mutates every route/service/plugin — control-plane takeover.
- **Kubernetes API server exposure**: `/version` and `/api/v1/namespaces` — a `200` (or anonymous-allowed `403` that still lists) on an internet-facing API server is critical; `/.well-known/openid-configuration` confirms a kube API and leaks the OIDC issuer for the federation checks above.

## Event-Driven Surface

Event/messaging endpoints are message-injection and data-exfiltration surfaces that host-focused recon skips entirely.

- **AWS EventBridge**: API-destination and Pipes targets can expose HTTPS endpoints; a public API destination or an over-permissive bus policy (`events:PutEvents` from `*`) lets an attacker inject events (`aws events list-api-destinations`, `aws events describe-event-bus`).
- **GCP Eventarc**: triggers invoke public Cloud Run URIs (`run.app` hosts above) — the trigger target URI is the surface (`gcloud eventarc triggers list`).
- **Azure Event Grid**: topic endpoints `https://<topic>.<region>-1.eventgrid.azure.net/api/events` — a topic with key auth disabled or a leaked SAS accepts injected events.
- **Azure Service Bus**: `https://<namespace>.servicebus.windows.net` — a leaked SAS (`Endpoint=sb://...;SharedAccessKey=...`) is queue/topic read/write.
- **Kafka REST proxy**: `/topics`, `/topics/<t>/records` on a Confluent REST proxy — an exposed proxy allows topic read/produce with no Kafka client.
- **MQTT-over-WebSocket**: `wss://<host>:443/mqtt` or `/ws` (IoT backends); anonymous connect + wildcard subscribe (`#`) leaks all device traffic.
- **WebPubSub / SignalR**: `https://<name>.webpubsub.azure.com` and SignalR `/negotiate` — a `negotiate` that issues a token to an unauthenticated client is a real-time-channel takeover.

**Event endpoint probes**:

```bash
# Azure Event Grid topic reachability (injection needs a key/SAS)
curl -s -o /dev/null -w '%{http_code}\n' 'https://<topic>.<region>-1.eventgrid.azure.net/api/events?api-version=2018-01-01'
# Confluent Kafka REST proxy topic listing
curl -s https://<host>/topics | jq -r '.[]' 2>/dev/null
# SignalR / WebPubSub negotiate (token issued to an unauth client = takeover)
curl -s -o /dev/null -w '%{http_code}\n' https://<name>.webpubsub.azure.com/client/negotiate
```

## Cloud Metadata Reconnaissance Signals

Metadata endpoints are not reachable from outside — but once a target has SSRF or a compute foothold, **this file's entire enumeration list becomes the SSRF chain target list**. Recognize the metadata signals and hand exploitation to `ssrf`.

- **AWS IMDS**: `http://169.254.169.254/latest/meta-data/`. IMDSv1 answers a bare `GET` (no token) — its presence is a misconfiguration. IMDSv2 requires a session token:

```bash
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

  (verified against AWS docs 2026-09-13). A bare GET returning data = IMDSv1 enabled (weaker SSRF bar). IMDSv2's PUT-then-GET is harder to reach via naive SSRF, but request-smuggling or a full-SSRF primitive still reaches it.
- **GCP metadata**: `http://metadata.google.internal/computeMetadata/v1/` — requires header `Metadata-Flavor: Google`. Newer GKE runs a **concealed metadata** proxy blocking pods from the raw endpoint; legacy/Standard clusters without it expose it directly — this distinction decides whether a pod SSRF reaches node credentials.
- **Azure IMDS**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01` — requires header `Metadata: true` and a versioned `api-version`. `/metadata/identity/oauth2/token?resource=...` mints managed-identity tokens.
- **IMDSv2 hop-limit**: the response hop limit (default 1) is meant to stop containers/proxies relaying metadata; it is still frequently raised to 2+ for container networking in 2024-2026, re-enabling container-SSRF-to-metadata. Treat a hop limit >1 as a live chain.
- **The pivot**: when metadata is reachable, enumerate `iam/security-credentials/` (AWS), `instance/service-accounts/default/token` (GCP), `identity/oauth2/token` (Azure) — the returned credentials scope back into every path above. Load `ssrf` for request construction and chain methodology.

## Tooling and Command Reference

Provider CLIs enumerate far more than passive probing — if any credential leaks on the target, use the CLI before rotation. Enumeration/graphing tools by provider:

**AWS**
- `pacu` — modular AWS exploitation framework (enumeration modules first)
- `aws-recon` / `cloudmapper collect` — surface mining and account graphing
- `enumerate-iam` — brute the effective permissions of a leaked key
- `s3-account-search` — attribute a bucket to an account id; `AWSBucketDump` — bucket wordlist enumeration
- `prowler` / `cloudsploit` — misconfiguration scan (read-only audit principal)

**Azure**
- `roadrecon` (roadtools) — Entra ID directory enumeration from a token (`roadrecon gather` then `roadrecon dump`)
- `azurehound` — BloodHound data collector for Entra/Azure
- `stormspotter` — attack-graph builder; `MicroBurst` — PowerShell recon module set

**GCP**
- `gcp-scanner` (Google) — enumerate access from a leaked credential/token
- `gcpbucketbrute` — unauthenticated GCS bucket + ACL enumeration
- `gcp-iam-collector` — IAM relationship graphing; `hayat` — GCP audit

**Multi-cloud**
- `cloudlist` (ProjectDiscovery) — asset enumeration across providers from configured keys (pairs with `subfinder`/`httpx`)
- `steampipe` — SQL over live cloud APIs (`select name from aws_s3_bucket where bucket_policy_is_public`)
- `cartography` — Neo4j asset/relationship graph across AWS/GCP/Azure/GitHub/Okta
- `cloudsploit` — cross-provider misconfiguration scanning

**Serverless / edge / mesh**
- `lambda-guard` — Lambda config audit
- `wrangler` (Cloudflare), `vercel`, `netlify`, `fly`, `railway` CLIs — each enumerates the account's projects/deployments if a token leaks (check token exposure first)
- `kubectl` (any leaked kubeconfig), `istioctl` — cluster/mesh inspection

Do not run destructive tooling (`aws-nuke` and similar) against a target account — use those only in an owned test account, for enumeration-behavior study.

## What Deep Cloud Recon Completeness Looks Like

Cloud recon is done only when:

- Every cloud provider the target uses is identified (AWS / Azure / GCP + which edge platforms)
- Per-provider runtime surface is enumerated: serverless URLs (Lambda/Functions/Cloud Run/App Engine), container ingress (ELB/App Gateway/GCLB, mesh gateways), and App Service/Container Apps/Container Instances hosts
- Storage endpoints are enumerated per provider (S3/Blob+ADLS+File+Table+Queue/GCS + Cosmos/BigQuery), with public-access state checked
- Edge deployment surface is discovered (Vercel/Netlify/Cloudflare Pages+Workers/Deno/Fly/Railway/Render), **including preview/branch deployments**
- Cross-tenant federation relationships are mapped where discoverable (SSO portals, B2B guest access, workload-identity trust, cross-account role trust)
- Ephemeral compute is catalogued (CI egress ranges, Codespaces/Gitpod forwarded ports, PR preview environments)
- Container ingress/control-plane endpoints are catalogued if the target is Kubernetes-native (mesh dashboards, Traefik/Kong/Ambassador admin, kube API exposure)
- Metadata reachability is noted as an SSRF-chain signal per compute surface

Only then scope hunters to the cloud-native classes: SSRF-to-metadata chains, IAM/federation misconfiguration, storage bucket abuse, admission-webhook and mesh-bypass exploitation, and preview-environment secret exposure.

## Pro Tips

1. Provider CLIs reveal more than any passive method — if a credential leaks, run `aws`/`az`/`gcloud`/`wrangler` enumeration immediately, before it rotates.
2. CT does not find wildcard-fronted serverless/edge subdomains — for `*.run.app`/`*.on.aws`/`*.vercel.app`/`*.workers.dev`, source-mine bundles and mine the org's git for branch names; use CT only for custom domains bound to the platform.
3. Deterministic URL formats (Cloud Run `<service>-<project-number>.<region>.run.app`, App Engine `<service>-dot-<project>.appspot.com`) are guessable — leak the project number/id and construct the URL instead of discovering it.
4. Preview and branch deployments are the softest surface on the platform — less auth, dev secrets, never deleted; mine every open and closed PR for their URLs.
5. Cross-tenant federation is routinely forgotten by the target — a years-old trust to a departed partner still assumes internal roles; enumerate the trust graph, not just hosts.
6. Edge-platform tokens (Cloudflare/Vercel/Netlify API) enumerate the whole account's projects — grep leaked bundles and CI config for these tokens first.
7. IMDSv2 enforcement and hop-limit are inconsistent even in 2025-2026 — always test IMDSv1 (bare GET) and treat a metadata hop limit >1 as a live container-SSRF chain.
8. Mesh and ingress control planes (Envoy `:15000`, Kong `:8001`, Traefik `/api/rawdata`, Kiali) are frequently exposed on internal LBs — probe them whenever the kube API or a mesh is reachable.
9. Every runtime is region- and environment-scoped — a target's staging region/subscription/preview environment usually mirrors prod naming with weaker controls; enumerate each independently.

## Summary

This deep sibling to `asset_discovery` maps cloud runtime surface: serverless URLs, container ingress, storage endpoints, edge/JAMstack deployments, cross-tenant federation trust, ephemeral compute, event-driven endpoints, and container-mesh control planes — the layer above the base file's cloud-range attribution, where cloud-native bugs live. It loads only in deep mode. Completeness means per-provider runtime + storage + edge + federation + ephemeral + ingress enumeration, with metadata reachability noted as the SSRF-chain signal, before cloud-native hunters are scoped. Companion deep siblings `asset_discovery_saas_deep` and `asset_discovery_historical_deep` cover tenant/IdP and historical/OSINT surface respectively.
