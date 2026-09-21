---
name: asset-discovery-saas-deep
description: Advanced SaaS and identity provider tenant discovery, modern platform correlation, and AI/ML platform footprint enumeration. Loaded automatically by deep scan mode as a companion to asset_discovery.md. Covers Okta/Auth0/Entra/Google Workspace tenant patterns, collaboration platforms (Slack/Confluence/Notion/Jira), developer platforms (GitHub/GitLab/Bitbucket), CI/CD platform correlation, marketing/analytics correlation, and 2024-2026 AI/ML platform footprints (OpenAI/Anthropic/HuggingFace/Replicate/LangSmith).
sibling: asset_discovery
load_when: scan_mode == "deep"
---

# Asset Discovery — SaaS / IdP Tenant (Deep)

This is the deep sibling to `asset_discovery` for SaaS and identity-provider tenant surface. The base file finds the org's hosts and domains; this file answers a different question — which SaaS platforms the target *uses*, and what tenant-level surface each exposes. A modern org's real attack surface is spread across dozens of third-party tenants (Okta, Slack, Jira, GitHub, an OpenAI org, a Hugging Face space) that never appear in a DNS/CT sweep of the org's own domains.

It loads only in deep scan mode. Two companion siblings cover adjacent scope: `asset_discovery_cloud_deep` (cloud runtime, serverless, edge — the provider infrastructure) and `asset_discovery_historical_deep` (historical, time-series, OSINT-derived). This file is the SaaS/IdP tenant layer between them — do not duplicate their content.

The workflow is two-phase: **identify** which platforms the target uses (from marketing/analytics tags in the site, DNS records, public docs and job posts naming tools, and the domains in SSO redirects), then **enumerate** the tenant surface on each. A recurring theme: SaaS tenant subdomains are usually the org's short name (`<company>.slack.com`, `<company>.atlassian.net`, `<company>.okta.com`), so once you have the org's naming convention, most tenants are guessable — confirm each rather than assume.

URL patterns and CVEs below verified against provider docs and vendor advisories 2026-09-13; where a platform is mid-transition (Microsoft Teams connectors), both the retiring and current form are given.

## Identity Provider Tenant Discovery

The IdP is the fastest route into a target's identity architecture — it names the federated apps, the tenant id, the auth model, and often the internal domains. Start here.

### Okta

**Pattern**: `https://<tenant>.okta.com` (also `<tenant>.oktapreview.com` for preview/sandbox, `<tenant>.okta-emea.com` for EMEA data residency, `<tenant>.okta-gov.com` for FedRAMP). Admin console at `<tenant>-admin.okta.com`.

```bash
# tenant is usually the org short name — confirm and read the OIDC metadata
curl -s https://<tenant>.okta.com/.well-known/openid-configuration | jq '{issuer,authorization_endpoint,token_endpoint}'
# SAML app metadata (app id from an SSO redirect)
curl -s https://<tenant>.okta.com/app/<app_id>/sso/saml/metadata
```

**Confirm**: a `200` OIDC-discovery JSON confirms the tenant exists; the `authorization_endpoint` host confirms Okta. Follow an SSO redirect from the target's login page — the `redirect_uri`/`client_id` and the `<tenant>.okta.com` host fall out of the 302 chain.

**Gotcha**: `oktapreview.com` sandboxes frequently mirror prod app config with weaker controls and test credentials — always check the preview tenant alongside prod. Okta Workflows can expose invokable URLs (`<tenant>.workflows.okta.com`) if a flow is set to an unauthenticated trigger.

### Auth0

**Pattern**: `https://<tenant>.auth0.com`, regionalized as `<tenant>.us.auth0.com`, `<tenant>.eu.auth0.com`, `<tenant>.au.auth0.com`, `<tenant>.jp.auth0.com`. Custom domains front many Auth0 tenants — resolve them back via the OIDC metadata.

```bash
curl -s https://<tenant>.auth0.com/.well-known/openid-configuration | jq '{issuer,jwks_uri}'
# a custom login domain reveals its Auth0 tenant in the issuer
curl -s https://login.<target>.com/.well-known/openid-configuration | jq -r .issuer
```

**Confirm**: the `issuer`/`jwks_uri` host is the real Auth0 tenant even behind a custom domain. Universal Login lives at `https://<tenant>.auth0.com/authorize`. Load `oauth`/`authentication_jwt` for the flow attacks.

**Gotcha**: the `jwks_uri` and `openid-configuration` are always unauthenticated — they confirm the tenant and hand you the signing keys for token analysis without any credential.

### Microsoft Entra ID (Azure AD)

**Pattern**: tenant vanity `<tenant>.onmicrosoft.com`; tenant id resolved from any owned domain.

```bash
# tenant id + endpoints from a domain (unauthenticated)
curl -s https://login.microsoftonline.com/<domain>/v2.0/.well-known/openid-configuration | jq -r '.issuer,.authorization_endpoint'
# GetUserRealm — reveals federation model (Managed vs Federated) and the AD FS host if federated
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1"
# enumerate valid onmicrosoft tenants + federated domains
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=probe@<domain>&xml=1" | grep -oE '<[A-Za-z]+>[^<]+'
```

**Confirm**: `GetUserRealm` returning `NameSpaceType=Federated` names the on-prem AD FS host (`AuthURL`), a high-value internal-facing surface; `Managed` means cloud-only. The OIDC `issuer` contains the tenant GUID. `AADInternals` (`Get-AADIntTenantDomains`, `Invoke-AADIntReconAsOutsider`) enumerates every domain federated to the tenant unauthenticated.

**Gotcha**: `getuserrealm.srf` and the openid-configuration are unauthenticated and rate-generous — they map the entire federation topology before you touch the target. AD FS endpoints (`/adfs/ls/`, `/adfs/services/trust/mex`) on the returned `AuthURL` are their own attack surface.

### Google Workspace

**Pattern**: no vanity subdomain — presence is inferred from mail and DKIM records.

```bash
dig +short mx <domain>              # aspmx.l.google.com / alt*.aspmx.l.google.com = Google Workspace
dig +short txt google._domainkey.<domain>   # Google DKIM selector present = Workspace
# Google Groups public archive for the domain
# https://groups.google.com/a/<domain>/forum/  (browse; public groups leak internal discussion)
```

**Confirm**: `aspmx.l.google.com` MX + a `google._domainkey` TXT confirm Workspace. Federated SSO (Workspace as SAML IdP or SP) shows in the login redirect chain. GCP project numbers leak from public GCS buckets the org owns — cross to `asset_discovery_cloud_deep`.

**Gotcha**: a public Google Group under `groups.google.com/a/<domain>` is a frequent internal-info leak; DKIM selector names (`google`, `selector1`, custom) fingerprint the mail stack.

Adjacent Google surfaces the org exposes without a vanity domain:
- **Apps Script web apps**: `https://script.google.com/macros/s/<deployment-id>/exec` — a deployed Apps Script running as the owner or "anyone"; a live, unauthenticated one is a real app endpoint (often with Sheets/Drive access on the backend).
- **Looker Studio (ex-Data Studio)**: public reports `https://lookerstudio.google.com/reporting/<report-id>` — frequently back live data sources (Sheets, BigQuery) with more than the intended view exposed.
- **Google Sites**: `https://sites.google.com/<domain>/<site>` or `/view/<site>` — internal wikis and onboarding sites published wider than intended.

```bash
grep -rhoE 'script\.google\.com/macros/s/[A-Za-z0-9_-]+/exec|lookerstudio\.google\.com/reporting/[A-Za-z0-9_-]+|sites\.google\.com/[a-z0-9.-]+/[A-Za-z0-9_-]+' bundles/ | sort -u
```

### OneLogin

**Pattern**: `https://<tenant>.onelogin.com`; API `https://<tenant>.onelogin.com/api/`; OIDC discovery `https://<tenant>.onelogin.com/oidc/2/.well-known/openid-configuration`.

```bash
curl -s https://<tenant>.onelogin.com/oidc/2/.well-known/openid-configuration | jq '{issuer,authorization_endpoint}' 2>/dev/null
```

**Gotcha**: the tenant is usually the org short name; the OIDC metadata confirms it and hands you the endpoints unauthenticated.

### PingIdentity

**Pattern**: PingOne cloud `https://auth.pingone.com/<env-id>/as/...` and `https://<tenant>.pingone.com`; self-hosted PingFederate at the org's SSO host (`/pf/heartbeat.ping`, `/idp/startSSO.ping`, `/.well-known/openid-configuration`).

```bash
curl -s https://<sso-host>/pf/heartbeat.ping 2>/dev/null      # PingFederate liveness
curl -s https://<sso-host>/.well-known/openid-configuration | jq -r .issuer 2>/dev/null
```

**Gotcha**: PingFederate self-hosted is version-fingerprintable and has had critical unauth CVEs — identify the exact build before assuming patched; the PingOne `<env-id>` (GUID) in a redirect scopes the tenant.

### JumpCloud / Duo / Rippling

**Patterns**: JumpCloud SSO `https://sso.jumpcloud.com/saml2/<app>` and OIDC `https://oauth.id.jumpcloud.com`; Duo `https://api-<hash>.duosecurity.com` (the `api-<hash>` host is per-customer); Rippling SSO under `app.rippling.com`.

```bash
grep -rhoE 'sso\.jumpcloud\.com/saml2/[a-z0-9-]+|api-[a-f0-9]+\.duosecurity\.com|oauth\.id\.jumpcloud\.com' bundles/ | sort -u
```

**Gotcha**: the Duo `api-<hash>` host is customer-specific and confirms Duo MFA in the auth chain — a signal for MFA-bypass and enrollment-abuse hunting; JumpCloud SAML app slugs name the federated apps.

### Custom OIDC providers

Any subdomain can be an OIDC issuer. Sweep the discovered subdomain set for the discovery document:

```bash
while read h; do
  code=$(curl -s -o /dev/null -w '%{http_code}' https://$h/.well-known/openid-configuration)
  [ "$code" = 200 ] && echo "OIDC: $h"; done < subdomains.txt
```

**Gotcha**: a self-hosted OIDC issuer (Keycloak `/realms/<realm>/.well-known/openid-configuration`, Dex, Ory Hydra) is both an auth boundary and a version-fingerprintable service — load `oauth`/`authentication_jwt`.

### Emerging B2B auth (WorkOS / Stytch / Frontegg / Clerk)

Newer auth/SSO platforms front the login and hold the tenant/SSO config:
- **WorkOS**: `https://api.workos.com`; hosted AuthKit `https://<slug>.authkit.app`; one SSO connection per enterprise customer.
- **Stytch**: `https://<env>.stytch.com` (`test`/`live`); public token in the bundle.
- **Frontegg**: `https://<subdomain>.frontegg.com`; hosted login.
- **Clerk**: `https://<slug>.clerk.accounts.dev` (dev) / `clerk.<domain>` (prod); Clerk publishable key `pk_(live|test)_<base64>` in the bundle.

```bash
grep -rhoE 'api\.workos\.com|[a-z0-9-]+\.authkit\.app|[a-z0-9-]+\.frontegg\.com|[a-z0-9-]+\.clerk\.accounts\.dev|(test|live)\.stytch\.com' bundles/ | sort -u
```

**Gotcha**: the frontend API on these platforms reveals the enabled auth factors and social/enterprise connections to attack; publishable keys are client-side by design, but a per-customer SSO connection slug enumerates the target's enterprise customers. Load `oauth` / `authentication_jwt`.

## Collaboration Platforms

Collaboration tenants leak internal names, project structure, and frequently documents. Tenant subdomains are almost always the org short name.

### Slack

**Pattern**: `https://<workspace>.slack.com`. Enterprise Grid orgs use a shared org with multiple workspaces; standard plan is one workspace per subdomain.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<company>.slack.com/     # 200/302 to sign-in = workspace exists
# the sign-in page reveals SSO enforcement and Grid vs standard
curl -s https://<company>.slack.com/ | grep -oE '"(is_enterprise|sso_required|team_name)":[^,]+'
```

**Confirm**: the workspace sign-in page exposes `team_name`, whether SSO is required, and Grid membership. Slack Connect shared channels bridge the target to partner orgs — a partner's laxer workspace is a lateral path.

**Gotcha**: workspace URLs are guessable from the org name; the sign-in page is public even when the workspace is invite-only. A leaked Slack token (`xoxb-`/`xoxp-` in a bundle or repo) enumerates the whole workspace via `https://slack.com/api/auth.test` then `conversations.list` — check for token exposure first.

### Microsoft Teams

**Pattern**: Teams tenancy is the Entra tenant (above); external/guest access is the reconnaissance surface. **Incoming-webhook currency note**: the legacy Office 365 Connector webhooks at `<tenant>.webhook.office.com/webhookb2/...` are **retired** — new connectors were blocked 2024-08-15 and existing ones disabled 2026-05-18, so a `webhook.office.com` URL found today is likely dead. The live equivalent is a Power Automate Workflow HTTP-trigger URL (`https://<region>.logic.azure.com:443/workflows/<id>/triggers/manual/paths/invoke?...&sig=<sig>`) — see the Logic Apps entry in `asset_discovery_cloud_deep`.

```bash
# federation/guest reachability probe uses the Entra tenant discovery above
curl -s "https://login.microsoftonline.com/getuserrealm.srf?login=user@<domain>&xml=1"
```

**Gotcha**: a leaked `webhook.office.com` URL is a dead end now; a leaked Workflow `sig=` URL still fires (data write / notification injection). External-access policy (open federation) lets an attacker-controlled tenant chat/meet with target users.

### Atlassian: Confluence Cloud

**Pattern**: `https://<tenant>.atlassian.net/wiki`. Anonymous access, when enabled, exposes spaces and pages.

```bash
curl -s "https://<tenant>.atlassian.net/wiki/rest/api/space?limit=100" | jq -r '.results[].key' 2>/dev/null
curl -s "https://<tenant>.atlassian.net/wiki/rest/api/content?type=page&limit=50" | jq -r '.results[].title' 2>/dev/null
```

**Confirm**: a JSON space/content listing means anonymous access is on — a common internal-info leak. Load the framework skill for exploitation of self-hosted Confluence (below).

**Gotcha**: self-hosted Confluence Data Center/Server has a run of critical, CISA-KEV CVEs — CVE-2022-26134 (unauth OGNL RCE), CVE-2023-22515 (unauth admin creation), CVE-2023-22518 (improper authorization, CVSS 10.0), CVE-2023-22527 (template-injection RCE). Fingerprint the exact build (`/wiki/rest/applinks/1.0/manifest`, footer version) before assuming patched; do not fire these blind.

### Notion

**Pattern**: published sites `https://<team>.notion.site`; app pages `https://www.notion.so/<workspace>/<page-title>-<32-hex-id>`; public API integration via a token (`ntn_...`/`secret_...`).

```bash
grep -rhoE '[a-z0-9-]+\.notion\.site[^"'"'"' ]*|notion\.so/[A-Za-z0-9-]+/[A-Za-z0-9-]+-[0-9a-f]{32}' bundles/ | sort -u
```

**Gotcha**: published Notion sites are search-indexed and frequently expose internal wikis, roadmaps, and onboarding docs the owner assumed were obscure; a leaked integration token reads every page the integration is shared into.

### Miro

**Pattern**: boards `https://miro.com/app/board/<board-id>/` (board id ends `=`); embedded/live-embed boards leak from `<iframe src>` on the target's site.

```bash
grep -rhoE 'miro\.com/app/(board|live-embed)/[A-Za-z0-9_=-]+' bundles/ | sort -u
```

**Gotcha**: a board set to "anyone with the link" (very common for embeds) is fully readable — architecture diagrams and credentials on sticky notes are the recurring leak.

### Coda

**Pattern**: docs `https://coda.io/d/<slug>_d<doc-id>`; embedded docs via `<iframe>`; API `https://coda.io/apis/v1/docs` with a token.

```bash
grep -rhoE 'coda\.io/d/[A-Za-z0-9_-]+' bundles/ | sort -u
```

**Gotcha**: a shared Coda doc often contains live tables (budgets, vendor lists, credentials) rather than static text — treat it as a data source, not a page.

### Airtable

**Pattern**: bases `https://airtable.com/app<id>`; shared views `https://airtable.com/shr<id>`; published forms `https://airtable.com/shr<id>` (accept input). The prefix decides access: `shr` = public share, `app` = needs auth.

```bash
grep -rhoE 'airtable\.com/(app|shr|tbl)[A-Za-z0-9]+' bundles/ | sort -u
```

**Gotcha**: a `shr`-prefixed link is a public read of the underlying base — shared views frequently expose far more columns/rows than the owner realizes; published forms are a data-injection surface.

### Figma

**Pattern**: files `https://www.figma.com/file/<key>/` (and newer `/design/<key>/`), prototypes `/proto/<key>/`; community profiles `/@<handle>`.

```bash
grep -rhoE 'figma\.com/(file|design|proto)/[A-Za-z0-9]+' bundles/ | sort -u
```

**Gotcha**: a public Figma file/prototype leaks unreleased UI, internal admin screens, and API responses baked into mockups; comments on shared files sometimes name employees and internal URLs.

### Discord

**Pattern**: community servers via invite `https://discord.gg/<invite>`; webhook URLs `https://discord.com/api/webhooks/<id>/<token>`.

```bash
grep -rhoE 'https://discord(app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_-]+' bundles/ | sort -u
```

**Gotcha**: a leaked Discord webhook URL posts arbitrary messages to the target's channel (phishing/impersonation); mine bundles and public repos for them.

## Ticketing and Project Management

### Jira Cloud

**Pattern**: `https://<tenant>.atlassian.net` (same tenant as Confluence Cloud). Anonymous project/issue access is a frequent leak.

```bash
curl -s "https://<tenant>.atlassian.net/rest/api/2/project" | jq -r '.[].key' 2>/dev/null
# anonymous JQL search when permitted
curl -s "https://<tenant>.atlassian.net/rest/api/2/search?jql=created>=-90d&maxResults=50&fields=summary" | jq -r '.issues[].fields.summary' 2>/dev/null
# user picker leaks employee names/emails when open
curl -s "https://<tenant>.atlassian.net/rest/api/2/user/search?query=a" | jq -r '.[].displayName' 2>/dev/null
```

**Confirm**: any JSON result means anonymous access is enabled — project keys, issue summaries, and the user picker are all internal-info leaks. The `/rest/api/2/user/search` picker is a common employee-enumeration oracle.

### Jira / Confluence Server & Data Center

**Pattern**: self-hosted at any host; version-fingerprint before anything.

```bash
curl -s https://<host>/rest/api/2/serverInfo | jq '{version,deploymentType}' 2>/dev/null
curl -s https://<host>/secure/Dashboard.jspa | grep -oiE 'version[^<]*[0-9]+\.[0-9]+\.[0-9]+'
```

**Gotcha**: self-hosted Jira/Confluence carries the critical CVEs noted above plus Jira's CVE-2019-11581 / CVE-2021-26086 class — the `serverInfo` version decides which apply. Never fire an RCE chain without the version.

### Trello

**Pattern**: boards `https://trello.com/b/<id>/<slug>`; the public REST API exposes public boards without auth.

```bash
curl -s "https://api.trello.com/1/members/<user>/boards?fields=name,url" | jq -r '.[].url' 2>/dev/null
curl -s "https://api.trello.com/1/search?query=<org>&modelTypes=boards&board_fields=name,url" 2>/dev/null | jq -r '.boards[].url'
```

**Gotcha**: Trello public boards have leaked credentials, customer lists, and internal plans at scale — the public API and search make them enumerable by org name; check explicitly.

### Linear / Asana / Monday / ClickUp / Height

**Patterns**: Linear `https://linear.app/<workspace>/...` (public share links); Asana `https://app.asana.com/0/<project-id>/...` (public projects); Monday `https://<account>.monday.com`; ClickUp public lists `https://sharing.clickup.com/<id>`; Height `https://height.app/<workspace>`.

```bash
grep -rhoE 'https://(linear\.app|app\.asana\.com|trello\.com/b|[a-z0-9-]+\.monday\.com|sharing\.clickup\.com|height\.app)[^"'"'"' ]*' bundles/ | sort -u
for a in <org> <org>-team <company>; do
  echo "$a $(curl -s -o /dev/null -w '%{http_code}' https://$a.monday.com/)"; done
```

**Gotcha**: `<account>.monday.com` is guessable from the org name and the sign-in page confirms existence; public share links to Linear/Asana/ClickUp objects leak roadmap and issue detail — mine the target's site and help center for embedded ones.

### ServiceNow

**Pattern**: `https://<instance>.service-now.com`; instance is the org short name or a sub-prod suffix (`<org>dev`, `<org>test`, `<org>uat`). Service Portal at `/sp`, public knowledge base via the Table API when anonymous access is misconfigured.

```bash
for i in <org> <org>dev <org>test <org>uat; do
  echo "$i $(curl -s -o /dev/null -w '%{http_code}' https://$i.service-now.com/)"; done
curl -s "https://<instance>.service-now.com/api/now/table/kb_knowledge?sysparm_limit=5" 2>/dev/null | jq '.result | length'
```

**Gotcha**: `<org>dev`/`<org>test` instances frequently mirror prod with weaker ACLs and real data; ServiceNow has had unauthenticated data-exposure and RCE CVEs (e.g. the CVE-2024-4879 / widget-ACL class) — version-fingerprint via the `/login.do` / `/stats.do` build before probing, and treat a widely-readable `kb_knowledge`/`incident` table as a real ACL finding.

## Document and File Platforms

### SharePoint / OneDrive

**Pattern**: SharePoint `https://<tenant>.sharepoint.com` (sites at `/sites/<site>`, `/teams/<team>`); OneDrive for Business `https://<tenant>-my.sharepoint.com/personal/<user>_<tenant>_com`; personal OneDrive `https://onedrive.live.com`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://<tenant>.sharepoint.com/     # tenant existence
```

**Gotcha**: `<tenant>` for SharePoint is the same string as the Entra `<tenant>.onmicrosoft.com` prefix — resolve it once from the IdP step. Anonymous "anyone with the link" shares are the leak; the site itself usually requires auth.

### Dropbox

**Pattern**: shared links `https://www.dropbox.com/scl/fi/<id>/...` and `/s/<id>/...`; Paper docs `https://paper.dropbox.com/doc/...`; team space at `www.dropbox.com/home`.

```bash
grep -rhoE 'dropbox\.com/(scl/fi|s|sh)/[^"'"'"' ]+|paper\.dropbox\.com/doc/[^"'"'"' ]+' bundles/ | sort -u
```

**Gotcha**: "anyone with the link" is the default share; a leaked Dropbox shared link is a public read regardless of the account's other controls.

### Box

**Pattern**: enterprise `https://<enterprise>.app.box.com`; shared links `https://<enterprise>.app.box.com/s/<hash>` or `https://app.box.com/s/<hash>`.

```bash
grep -rhoE '([a-z0-9-]+\.)?app\.box\.com(/s/[a-z0-9]+)?' bundles/ | sort -u
```

**Gotcha**: the `<enterprise>` subdomain confirms the tenant; open shared links (`/s/<hash>`) are public and, with folder shares, expose whole directory trees.

### Google Drive

**Pattern**: folders `https://drive.google.com/drive/folders/<id>`; files `https://drive.google.com/file/d/<id>`; published docs `https://docs.google.com/{document,spreadsheets,presentation}/d/<id>`.

```bash
grep -rhoE 'drive\.google\.com/(drive/folders|file/d)/[A-Za-z0-9_-]+|docs\.google\.com/(document|spreadsheets|presentation)/d/[A-Za-z0-9_-]+' bundles/ | sort -u
```

**Gotcha**: mine the target's site, help-center, and public docs for embedded/shared links — a folder set to "anyone with the link" exposes every file inside; published Sheets often back live dashboards with real data.

## Developer Platforms

Developer-platform tenants expose more of an org's code, employees, and infrastructure than almost any other SaaS surface.

### GitHub organizations

**Pattern**: `https://github.com/<org>`; Pages `https://<org>.github.io`.

```bash
curl -s https://api.github.com/orgs/<org> | jq '{login,name,blog,email,public_repos}'
gh api /orgs/<org>/members --paginate --jq '.[].login' 2>/dev/null      # public members = employees
gh search repos --owner <org> --limit 200 --json name,visibility,pushedAt 2>/dev/null
gh search code --owner <org> 'okta.com OR onelogin OR internal' 2>/dev/null   # cross-repo secret/host mining
```

**Confirm**: public org members are employees often missed by LinkedIn enumeration; `blog`/`email` fields and repo `homepage`s link org-owned domains. Org-owned domains also surface via `*.githubusercontent.com` cert SANs and repo `CNAME` files (Pages custom domains).

**Gotcha**: GitHub Discussions and wiki are public archives; a forked-then-made-public internal repo, or a public repo's git history, leaks more than the current tree — mine history, not just HEAD. GitHub Copilot Workspace / Codespaces forwarded ports cross to `asset_discovery_cloud_deep`.

### Package registries

An org's published packages often expose more code and internal names than its GitHub. Enumerate by namespace/user:
- **npm** scope `@<scope>`: `https://www.npmjs.com/org/<scope>`, registry `https://registry.npmjs.org/-/org/<scope>/package`.
- **PyPI** `https://pypi.org/user/<user>/`; **RubyGems** `https://rubygems.org/profiles/<user>`; **crates.io** `https://crates.io/users/<user>`; **Maven Central** by groupId `https://repo1.maven.org/maven2/<group/path>/`; **NuGet** `https://www.nuget.org/profiles/<user>`.

```bash
grep -rhoE '@[a-z0-9-]+/[a-z0-9._-]+' bundles/ package*.json 2>/dev/null | sort -u
curl -s "https://registry.npmjs.org/-/v1/search?text=maintainer:<user>&size=250" | jq -r '.objects[].package.name' 2>/dev/null
```

**Gotcha**: an **unclaimed** npm scope, or an internal package name referenced in a lockfile but absent from the public registry, is a dependency-confusion lead — load `npx_confusion` / `infrastructure_lifecycle`. Published package `repository`/`homepage` fields link org domains and the source repo.

### Container registries

**Patterns**: Docker Hub `hub.docker.com/u/<org>` + registry API; GHCR `ghcr.io/<org>/<image>`; Quay `quay.io/<org>`; Google Artifact Registry `<region>-docker.pkg.dev/<project>/<repo>`; AWS ECR Public `public.ecr.aws/<alias>`.

```bash
curl -s "https://hub.docker.com/v2/repositories/<org>/?page_size=100" | jq -r '.results[].name' 2>/dev/null
grep -rhoE 'ghcr\.io/[a-z0-9-]+/[a-z0-9._/-]+|[a-z0-9-]+-docker\.pkg\.dev/[a-z0-9-]+/[a-z0-9._/-]+|public\.ecr\.aws/[a-z0-9]+' bundles/ *.yaml *.yml Dockerfile* 2>/dev/null | sort -u
```

**Gotcha**: a public container image frequently ships the full app plus baked-in secrets (`.env` copied into a layer, cloud keys in a build arg) — pull and inspect layers (`docker history`, `dive`) before assuming the image is clean.

### IaC registries

**Patterns**: Terraform Registry `https://registry.terraform.io/namespaces/<ns>` (modules/providers); Pulumi Registry `https://www.pulumi.com/registry/packages/`; Ansible Galaxy `https://galaxy.ansible.com/<namespace>`.

**Gotcha**: a published Terraform module or Ansible collection encodes the org's infra conventions (naming, regions, provider setup) and sometimes example values that mirror production — a blueprint for the cloud enumeration in `asset_discovery_cloud_deep`.

### GitLab / Bitbucket / alternatives

**Patterns**: GitLab groups `https://gitlab.com/<group>`, subgroups `<group>/<subgroup>`, Pages `https://<group>.gitlab.io/<project>`, self-hosted at any host (`/api/v4/version`); Bitbucket Cloud `https://bitbucket.org/<workspace>`; alternatives SourceForge `sourceforge.net/u/<user>`, Codeberg `codeberg.org/<org>`, sr.ht `sr.ht/~<user>`.

```bash
curl -s "https://gitlab.com/api/v4/groups/<group>/projects?per_page=100" | jq -r '.[].path_with_namespace' 2>/dev/null
curl -s "https://api.bitbucket.org/2.0/repositories/<workspace>?pagelen=100" | jq -r '.values[].full_name' 2>/dev/null
```

**Gotcha**: self-hosted GitLab (`/api/v4/version`, needs a token, or the footer) gates a long CVE list — fingerprint first; public GitLab snippets and Bitbucket repos leak the same secrets as public GitHub.

## CI/CD Platform Correlation

Public CI surfaces leak workflow logic, secrets in logs, and self-hosted-runner IPs.

### GitHub Actions

**Pattern**: runs `https://github.com/<org>/<repo>/actions`; workflow files under `.github/workflows/` in every public repo.

```bash
gh api "/repos/<org>/<repo>/contents/.github/workflows" --jq '.[].name' 2>/dev/null
gh api "/repos/<org>/<repo>/actions/runs?per_page=100" --jq '.workflow_runs[] | {name,conclusion,url}' 2>/dev/null
```

**Gotcha**: public run logs frequently expose secrets echoed by misconfigured steps and the internal hostnames a deploy touches; `runs-on: [self-hosted, ...]` labels name the target's own infra (self-hosted-runner egress correlates to the target VPC — cross to `asset_discovery_cloud_deep`); `pull_request_target` + checkout of PR code is a supply-chain lead.

### CircleCI

**Pattern**: `https://app.circleci.com/pipelines/github/<org>/<repo>`; config `.circleci/config.yml` in-repo.

```bash
curl -s "https://circleci.com/api/v2/insights/gh/<org>/<repo>/workflows" 2>/dev/null | jq -r '.items[].name'
```

**Gotcha**: CircleCI orbs referenced in the config name third-party build dependencies; historical CircleCI incidents make any long-lived project token in the config high-value.

### GitLab CI

**Pattern**: pipelines under the project (`/-/pipelines`); `.gitlab-ci.yml` in-repo; job artifacts and logs public when the project is.

```bash
curl -s "https://gitlab.com/api/v4/projects/<id>/pipelines?per_page=50" | jq -r '.[].web_url' 2>/dev/null
```

**Gotcha**: public job logs and artifacts leak the same secrets/hostnames as Actions; `CI_*` variables echoed in logs are the common exposure.

### Jenkins / CloudBees

**Pattern**: self-hosted at any host; `/api/json`, `/login` banner, `/oops`/`/whoAmI` for version.

```bash
curl -s https://<host>/api/json?pretty=true 2>/dev/null | jq '{mode,useSecurity,jobs:[.jobs[].name]}'
curl -sI https://<host>/ | grep -i '^x-jenkins'     # x-jenkins: <version>
```

**Gotcha**: `x-jenkins` version-fingerprints the instance for its long CVE list; an unauthenticated `/api/json` listing jobs, or `/script` (Groovy console) reachable, is critical — never fire blind, confirm auth state first.

### Others — Travis / Buildkite / Drone / Bitrise

**Patterns**: Travis `https://app.travis-ci.com/github/<org>`; Buildkite `https://buildkite.com/<org>`; Drone/Woodpecker self-hosted; Bitrise `https://app.bitrise.io/app/<slug>` (mobile CI). App Center is retiring (migrate-to signal).

**Gotcha**: mobile CI (Bitrise, App Center) builds signed artifacts and holds signing keys/provisioning profiles — a compromised mobile-CI tenant is an app-supply-chain compromise.

## Marketing, Analytics, and Tracking Correlation

Analytics and tag IDs are the strongest link between sibling domains that WHOIS and DNS will not connect — the same GA4 property or GTM container across two domains proves common ownership. Harvest every ID from the target's pages, then reverse-lookup each to find every other property carrying it.

```bash
grep -rhoE 'G-[A-Z0-9]{10}|UA-[0-9]{4,}-[0-9]+|GTM-[A-Z0-9]{4,}|AW-[0-9]{9,}' bundles/ | sort -u
grep -rhoE 'cdn\.segment\.com/analytics\.js/v1/[A-Za-z0-9]+|app\.posthog\.com|eu\.posthog\.com|[a-z0-9]+\.hotjar\.com|widget\.intercom\.io' bundles/ | sort -u
```

### Google Analytics / Tag Manager

**Pattern**: `G-XXXXXXXXXX` (GA4), `UA-XXXXXX-N` (legacy Universal), `GTM-XXXXXXX` (Tag Manager container), `AW-XXXXXXXXX` (Google Ads). One ID across two domains proves common owner.

```bash
# reverse-lookup an ID to every site carrying it (no target access needed)
# publicwww:  https://publicwww.com/websites/%22G-XXXXXXXXXX%22/
# Shodan:     http.html:"G-XXXXXXXXXX"
```

**Gotcha**: the GTM container id is the highest-yield pivot — a shared `GTM-XXXX` links a marketing microsite, a careers domain, and the product domain that share nothing in DNS.

### Segment

**Pattern**: `https://cdn.segment.com/analytics.js/v1/<write-key>/analytics.min.js` — the write key is client-side.

**Gotcha**: the write key lets you send arbitrary events into the target's Segment pipeline (data poisoning / analytics abuse), and the loaded destinations in the snippet enumerate the downstream tools (which CDP/warehouse/marketing platforms the org feeds).

### Product analytics — Mixpanel / Amplitude / PostHog

**Patterns**: Mixpanel project token (32-hex) in the init call; Amplitude API key; PostHog cloud `app.posthog.com` / `eu.posthog.com` vs self-hosted (`<sub>.<target>.com` running PostHog).

```bash
grep -rhoE 'mixpanel\.init\(["'"'"'][a-f0-9]{32}|amplitude[^"'"'"' ]*apiKey["'"'"' :]+[A-Za-z0-9]{32}|posthog\.init\(["'"'"']phc_[A-Za-z0-9]+' bundles/ | sort -u
```

**Gotcha**: a self-hosted PostHog (`phc_` key + a non-posthog.com host) is an app the org runs — version-fingerprint it; its `/decide` and shared-insight URLs can leak feature flags and internal dashboards.

### Session recording — Hotjar / FullStory / LogRocket

**Patterns**: Hotjar `hjid` in the snippet (`static.hotjar.com/c/hotjar-<id>.js`); FullStory org id (`fs.js` + `_fs_org`); LogRocket app id (`<org>/<app>`).

**Gotcha**: session-recording tools capture keystrokes and DOM — a misconfigured recording (no input masking) stores credentials and PII in the vendor tenant; the tenant/org id fingerprints the vendor account.

### Support — Intercom / Zendesk / Freshdesk

**Patterns**: Intercom `app_id` in the widget (`widget.intercom.io/widget/<app_id>`); Zendesk help center `https://<tenant>.zendesk.com` (public, enumerable) and `<tenant>.zendesk.com/api/v2/help_center/articles.json`; Freshdesk `<tenant>.freshdesk.com`.

```bash
curl -s "https://<tenant>.zendesk.com/api/v2/help_center/articles.json?per_page=100" | jq -r '.articles[].title' 2>/dev/null
```

**Gotcha**: public Zendesk/Freshdesk help centers and community forums leak internal process docs and, in comments, employee names and ticket detail; the API paginates the whole public knowledge base unauthenticated.

### Payments — Stripe and others

**Pattern**: Stripe publishable key `pk_live_...` / `pk_test_...` in the bundle (public by design); Checkout sessions `https://checkout.stripe.com/c/pay/cs_...`.

```bash
grep -rhoE 'pk_(live|test)_[A-Za-z0-9]{20,}' bundles/ | sort -u
```

**Gotcha**: a `pk_test_` key on a production site is a test-mode misconfiguration (payments not real); a leaked **secret** key (`sk_live_...`) — distinct from the publishable one — is full account access, so distinguish the prefixes and never assume a `pk_` is sensitive.

**Correlation pivot**: reverse-lookup any GA/GTM id (publicwww, Shodan, BuiltWith) to find every other site running it — the highest-yield sibling-domain pivot, needing no access to the target.

## CDN, Edge, and Marketing Automation Tenancy

### CDN account correlation

Multiple domains under one CDN account correlate even without shared DNS:
- **Cloudflare**: shared `cf-ray` behaviors and shared custom-cert packs; a leaked Cloudflare API token enumerates every zone on the account (`GET /client/v4/zones`).
- **Fastly**: the `Fastly-Debug: 1` request header returns a `Fastly-Debug-*` response naming the service; the same service id across hosts ties them together. `x-served-by`/`x-cache` confirm Fastly.
- **Akamai / others**: `x-akamai-*` / `akamai-grn` headers; KeyCDN/BunnyCDN identifiable by their edge headers and `b-cdn.net` (Bunny) pull-zone hosts.

```bash
curl -sI -H 'Fastly-Debug: 1' https://<host>/ | grep -i '^fastly-debug\|^x-served-by\|^x-cache'
```

**Gotcha**: custom-domain certs on a shared CDN account appear in CT — cross-reference the base file's CT pivot to enumerate the account's other domains.

### Marketing automation — HubSpot / Marketo / Pardot

**Patterns**: HubSpot tracking `js.hs-scripts.com/<portal-id>.js`, forms `share.hsforms.com/<id>`, LP domains `<subdomain>.hs-sites.com`; Marketo `munchkin.js` with `<munchkin-id>` and LP domains `<subdomain>.marketo.com` / `info.<target>.com`; Pardot `pi.pardot.com` pixel + `go.pardot.com` LPs.

```bash
grep -rhoE 'js\.hs-scripts\.com/[0-9]+|[a-z0-9-]+\.hs-sites\.com|[a-z0-9-]+\.marketo\.com|munchkin\.init\(["'"'"'][0-9A-Z-]+' bundles/ | sort -u
```

**Gotcha**: the HubSpot portal id / Marketo munchkin id links otherwise-unconnected domains to the same owner; gated-asset URLs on these LPs frequently expose internal document links.

### Salesforce Experience / Community

**Pattern**: Experience Cloud/Community sites `https://<org>.force.com`, `https://<org>.my.salesforce-sites.com`, and newer `https://<org>.my.site.com`; the org instance `https://<org>.my.salesforce.com`. Guest-accessible Apex/Aura endpoints live under `/s/` and `/services/`.

```bash
grep -rhoE '[a-z0-9-]+\.(force\.com|my\.salesforce-sites\.com|my\.site\.com|my\.salesforce\.com)' bundles/ | sort -u
# guest-user Aura endpoint presence (a real, unauth-testable app surface)
curl -s -o /dev/null -w '%{http_code}\n' 'https://<org>.my.site.com/s/sfsites/aura'
```

**Gotcha**: Salesforce Experience/Community sites are a recurring source of unauthenticated object exposure via guest-user profile over-permissioning and Aura `getRecord`/`getRecords` abuse — a `force.com`/`my.site.com` host is a real app surface to hunt, not a marketing page.

## AI/ML Platform Footprints (2024-2026)

The newest tenant surface, and the least-hardened. AI platforms hold prompt/response logs, training data, model artifacts, and API keys — and orgs stand them up faster than they secure them. Patterns verified 2026-09-13.

### OpenAI

**Pattern**: the org id (`org-<id>`) appears in API responses and some client configs; custom GPTs `https://chatgpt.com/g/<gpt-id>`; Assistants via the API. Keys `sk-...` / `sk-proj-...` (project-scoped).

```bash
grep -rhoE 'org-[A-Za-z0-9]{20,}|chatgpt\.com/g/[A-Za-z0-9-]+' bundles/ | sort -u
grep -rhoE 'sk-proj-[A-Za-z0-9_-]{20,}|sk-[A-Za-z0-9]{20,}' bundles/ | sed 's/\(sk-[a-z-]*......\).*/\1…[redacted]/' | sort -u
```

**Gotcha**: a leaked `sk-`/`sk-proj-` key is org- or project-scoped access on the target's account (and bill); a public custom GPT can leak its system prompt and any configured actions/knowledge files — enumerate the org's published GPTs.

### Anthropic

**Pattern**: Console `https://console.anthropic.com`; API `https://api.anthropic.com/v1/messages`; keys `sk-ant-...`; Workbench-shared prompts.

```bash
grep -rhoE 'api\.anthropic\.com|sk-ant-[A-Za-z0-9_-]{20,}' bundles/ | sed 's/\(sk-ant-......\).*/\1…[redacted]/' | sort -u
```

**Gotcha**: a leaked `sk-ant-...` key is org access; the `anthropic-version` header and model ids in the bundle fingerprint how the app calls the model (relevant for `llm_applications` prompt-injection testing).

### Azure OpenAI

**Pattern**: `https://<resource>.openai.azure.com` — a tenant-specific deployment host; the deployment name is in the path (`/openai/deployments/<name>/chat/completions?api-version=<ver>`).

```bash
grep -rhoE '[a-z0-9-]+\.openai\.azure\.com[^"'"'"' ]*' bundles/ | sort -u
```

**Gotcha**: `<resource>.openai.azure.com` is a guessable/mineable tenant host; an exposed Azure OpenAI key + the deployment name is full model access on the target's Azure account. Cross to `asset_discovery_cloud_deep` for the Azure tenant context.

### Google Gemini / Vertex AI

**Pattern**: Vertex `https://<region>-aiplatform.googleapis.com/v1/projects/<project>/locations/<region>/...`; Gemini API `https://generativelanguage.googleapis.com/v1beta/models/...?key=<AIza...>`. Usage is a GCP-project signal.

```bash
grep -rhoE '[a-z0-9-]+-aiplatform\.googleapis\.com|generativelanguage\.googleapis\.com|AIza[0-9A-Za-z_-]{35}' bundles/ | sort -u
```

**Gotcha**: an `AIza...` key restricted to the Generative Language API is client-usable model access on the org's bill if the key referrer/IP restrictions are loose; the `<project>` in a Vertex URL feeds the GCP enumeration in `asset_discovery_cloud_deep`.

### LangSmith

**Pattern**: cloud UI `https://smith.langchain.com` (US/GCP), EU region `https://eu.smith.langchain.com`; API `https://api.smith.langchain.com` (EU `https://eu.api.smith.langchain.com`). Access is workspace-scoped via `LANGSMITH_WORKSPACE_ID`; keys are `lsv2_pt_...` (personal) / `lsv2_sk_...`. Self-hosted LangSmith runs on the org's own host.

```bash
grep -rhoE 'https://(eu\.)?(api\.)?smith\.langchain\.com|lsv2_(pt|sk)_[A-Za-z0-9]+' bundles/ | sed 's/\(lsv2_[a-z]*_....\).*/\1…[redacted]/' | sort -u
```

**Gotcha**: a leaked `lsv2_` key plus the workspace id reads the org's LangSmith **traces** — full prompt/response/tool-call logs, the highest-value AI-era disclosure. The `LANGSMITH_ENDPOINT` in a bundle tells you cloud-region vs self-hosted.

### LangFuse

**Pattern**: cloud `https://cloud.langfuse.com` (US) and `https://cloud.langfuse.com` EU-region split vs self-hosted (`langfuse.<target>.com`); keys public `pk-lf-...`, secret `sk-lf-...`.

```bash
grep -rhoE 'cloud\.langfuse\.com|langfuse\.[a-z0-9.-]+|pk-lf-[A-Za-z0-9-]+' bundles/ | sort -u
```

**Gotcha**: self-hosted LangFuse is frequently stood up without SSO/auth in front — a reachable instance exposes traces and datasets; version-fingerprint the self-hosted build.

### Weights & Biases

**Pattern**: `https://wandb.ai/<entity>/<project>` (entity = user or team); reports `wandb.ai/<entity>/<project>/reports/...`; self-hosted at `wandb.<target>.com`.

```bash
curl -s -o /dev/null -w '%{http_code}\n' https://wandb.ai/<entity>     # public team/user
grep -rhoE 'wandb\.ai/[a-z0-9_-]+|api\.wandb\.ai' bundles/ | sort -u
```

**Gotcha**: public W&B projects/reports leak training runs, hyperparameters, dataset names, and sometimes artifact URLs with data; self-hosted W&B is a fingerprintable app.

### MLflow

**Pattern**: tracking server at any host; REST `/api/2.0/mlflow/experiments/search`, model registry `/api/2.0/mlflow/registered-models/search`. Ships with **no authentication** by default.

```bash
curl -s "https://<host>/api/2.0/mlflow/experiments/search" -H 'content-type: application/json' -d '{"max_results":1000}' | jq -r '.experiments[].name' 2>/dev/null
curl -s "https://<host>/api/2.0/mlflow/registered-models/search" | jq -r '.registered_models[].name' 2>/dev/null
```

**Gotcha**: an unauthenticated MLflow (very common) leaks every experiment, run parameter, and registered model; some MLflow versions also had an LFI/RCE via artifact path traversal (CVE-2023-6014/CVE-2024-27132 class) — fingerprint the version before probing artifacts.

### Comet ML

**Pattern**: `https://www.comet.com/<workspace>/<project>` (formerly comet.ml); self-hosted Comet on the org host.

**Gotcha**: public Comet workspaces expose experiment metrics and assets; the workspace name is guessable from the org name.

### Hugging Face

**Pattern** (verified 2026-09): org page `https://huggingface.co/<org>`; Spaces app `https://<user>-<space>.hf.space` (API at `/gradio_api/...`); dedicated Inference Endpoints `https://<hash>.<region>.<vendor>.endpoints.huggingface.cloud` (e.g. `jpj7k2q4j805b727.us-east-1.aws.endpoints.huggingface.cloud`).

```bash
curl -s "https://huggingface.co/api/models?author=<org>&limit=100" | jq -r '.[].id' 2>/dev/null
curl -s "https://huggingface.co/api/spaces?author=<org>&limit=100" | jq -r '.[].id' 2>/dev/null
grep -rhoE '[a-z0-9-]+\.hf\.space|[a-z0-9.-]+\.endpoints\.huggingface\.cloud|hf_[A-Za-z0-9]{30,}' bundles/ | sed 's/\(hf_......\).*/\1…[redacted]/' | sort -u
```

**Gotcha**: HF Spaces run arbitrary app code (Gradio/Streamlit) on the org's behalf — a public Space with a debug endpoint or an embedded key is a live target; dedicated Inference Endpoints set to `public` accept unauthenticated inference. A leaked `hf_...` token reads private models/datasets.

### Replicate

**Pattern**: `https://replicate.com/<user-or-org>/<model>`; API `https://api.replicate.com/v1/...`; deployment endpoints `https://api.replicate.com/v1/deployments/<owner>/<name>`.

```bash
grep -rhoE 'replicate\.com/[a-z0-9_.-]+/[a-z0-9_.-]+|r8_[A-Za-z0-9]{20,}' bundles/ | sed 's/\(r8_......\).*/\1…[redacted]/' | sort -u
```

**Gotcha**: a leaked `r8_...` token runs models on (and bills) the org's account; public model pages reveal what the org runs and their input schemas.

### Modal

**Pattern** (verified 2026-09): web endpoints `https://<workspace>[-<envsuffix>]--<label>.modal.run`, e.g. `ecorp-prod--speechify.modal.run`. The `<workspace>` (and env suffix) is org-identifying.

```bash
grep -rhoE '[a-z0-9-]+--[a-z0-9-]+\.modal\.run' bundles/ | sort -u
```

**Gotcha**: the workspace segment leaks the org and environment; a Modal web endpoint with no auth decorator is an open function invocation.

### Together / Fireworks / Anyscale

**Patterns**: Together OpenAI-compatible `https://api.together.xyz/v1` (verified); Fireworks `https://api.fireworks.ai/inference/v1`; Anyscale endpoints (OpenAI-compatible base). Usage shows as these hosts in the bundle plus a provider key.

```bash
grep -rhoE 'api\.(together\.xyz|fireworks\.ai)[^"'"'"' ]*' bundles/ | sort -u
```

**Gotcha**: these are OpenAI-compatible — a leaked provider key is model access on the org's bill; the base URL in the bundle tells you which inference provider the app trusts (a prompt-injection-relevant fact for `llm_applications`).

Vector databases are the newest AI-app surface and the least-secured: the self-hosted ones ship auth **off by default**, so a reachable instance is unauthenticated read (and usually write) of the org's embeddings — which can be inverted back to the source text they were built from.

### Pinecone

**Pattern** (serverless, verified 2026-09): `https://<index>-<id>.svc.<region>-<cloud>.pinecone.io`, e.g. `serverless-index-4zo0ijk.svc.us-west2-aws.pinecone.io`. Managed SaaS — access needs the API key, but the host + index name leak the data model.

```bash
grep -rhoE '[a-z0-9-]+\.svc\.[a-z0-9-]+-[a-z]+\.pinecone\.io' bundles/ | sort -u
```

**Gotcha**: a leaked Pinecone key (`pcsk_...` / older UUID form) plus the index host is full data-plane read/write; the index host itself names the region/cloud the RAG data lives in.

### Qdrant

**Pattern**: REST `:6333`, gRPC `:6334`; Qdrant Cloud `https://<cluster-id>.<region>.aws.cloud.qdrant.io:6333`.

```bash
curl -s http://<host>:6333/collections | jq -r '.result.collections[].name' 2>/dev/null
curl -s http://<host>:6333/telemetry | jq '{version:.result.app.version}' 2>/dev/null
```

**Gotcha**: default Qdrant has no API key — a `200` on `/collections` is unauthenticated access; `/telemetry` version-fingerprints it. Cloud clusters require a key but the host still confirms usage.

### Weaviate

**Pattern**: REST `:8080`, gRPC `:50051`; Weaviate Cloud `https://<cluster>.weaviate.network` / `<cluster>.<region>.gcp.weaviate.cloud`.

```bash
curl -s http://<host>:8080/v1/meta | jq '{version,modules}' 2>/dev/null
curl -s http://<host>:8080/v1/objects?limit=5 2>/dev/null | jq '.objects | length'
```

**Gotcha**: anonymous access is a config toggle often left on — `/v1/meta` returns version + enabled modules (e.g. a generative module wired to an LLM key), and `/v1/objects` reads stored vectors/text.

### ChromaDB / Milvus

**Patterns**: Chroma `:8000` (`/api/v1/collections`, v2 `/api/v2/...`); Milvus `:19530` (gRPC) + `:9091` (metrics/health).

```bash
curl -s http://<host>:8000/api/v1/collections | jq -r '.[].name' 2>/dev/null
curl -s http://<host>:9091/healthz 2>/dev/null   # Milvus health = instance present
```

**Gotcha**: Chroma and Milvus default to no auth; a reachable collection listing is the org's embedded corpus. Treat any exposed vector DB as both a disclosure (embedding inversion) and a poisoning target (write access corrupts RAG answers).

### OpenAI-compatible endpoint discovery

Many internal LLM proxies (LiteLLM, vLLM, Ollama, self-hosted gateways) expose the OpenAI schema. Probe the target's runtime surface for it:

```bash
curl -s https://<host>/v1/models | jq -r '.data[].id' 2>/dev/null      # 200 + model list = OpenAI-compatible proxy
for p in /v1/chat/completions /v1/embeddings /v1/models /api/generate; do
  echo "$p $(curl -s -o /dev/null -w '%{http_code}' https://<host>$p)"; done
```

**Gotcha**: an internal `/v1/chat/completions` reachable without a key is an open LLM proxy — model theft, cost abuse, and (if it has tools/RAG) a prompt-injection pivot. `/api/generate` + `/api/tags` is Ollama; load `llm_applications` for exploitation.

## Communication and Email Platforms

Transactional/marketing email platforms are fingerprintable from DNS and headers; their tenant surface (templates, unsubscribe hosts, webhooks, dangling ESP CNAMEs) leaks. The SPF record is a free inventory of every ESP the org authorizes:

```bash
dig +short txt <domain> | grep -oE 'include:[a-z0-9._-]+'     # each include: is an authorized sender
```

### Transactional ESPs — SendGrid / Mailgun / Postmark / SES

**Detection**: SPF `include:sendgrid.net` / `include:mailgun.org` / `include:_spf.mtasv.net` (Postmark) / `include:amazonses.com`; click/open-tracking hosts CNAME'd to the ESP (`<code>.ct.sendgrid.net`, `email.<target>.com` → ESP); DKIM selectors (`s1._domainkey`, `smtp._domainkey`).

```bash
grep -rhoE 'ct\.sendgrid\.net|[a-z0-9-]+\.mailgun\.org|api\.postmarkapp\.com|click\.[a-z0-9.-]+' bundles/ | sort -u
dig +short cname email.<domain> links.<domain> mail.<domain>   # tracking subdomains -> ESP
```

**Gotcha**: a tracking subdomain CNAME'd to a de-provisioned ESP zone is a subdomain-takeover lead (cross to `subdomain_takeover`); an SES/SendGrid tenant lets an attacker with a leaked key send mail from the target's verified domain.

### Twilio

**Pattern**: account SID `AC<32-hex>` and webhook/app URLs (`<host>/twilio/...`, `/voice`, `/sms`); TwiML bins `handler.twilio.com/twiml/<id>`.

```bash
grep -rhoE 'AC[0-9a-f]{32}|handler\.twilio\.com/twiml/[A-Za-z0-9]+' bundles/ | sort -u
```

**Gotcha**: a leaked `AC...` SID + auth token is full Twilio account access (send SMS/calls on the org's number, read logs); the account SID alone confirms Twilio usage.

### Marketing email — Braze / Iterable / Customer.io

**Patterns**: Braze SDK endpoint + API key in-app (`sdk.iad-*.braze.com`); Iterable `<key>` in the snippet; Customer.io `track.customer.io` / `<site-id>` in the JS; link domains CNAME'd to the platform.

```bash
grep -rhoE 'sdk\.[a-z0-9-]+\.braze\.com|track\.customer\.io|links?\.[a-z0-9.-]+' bundles/ | sort -u
```

**Gotcha**: these platforms hold the org's full contact list and message history; a leaked SDK/API key is customer-data access and message-injection.

### Shared inbox — Front / Missive

**Detection**: inferred from mail routing (MX/forwarding to the platform) and support-address behavior; Front `<workspace>.frontapp.com`.

**Gotcha**: shared-inbox platforms centralize support and sales mail — a compromised seat reads cross-team correspondence; presence is a phishing-target signal.

## Enrichment Sources

Passive/commercial sources that reveal a target's SaaS/vendor relationships without touching the target. These identify *which* platforms are in use so the per-platform probes above have something to point at.

- **Tech-stack + tag fingerprinters** (BuiltWith, Wappalyzer, **publicwww**, Netify): map SaaS/analytics tags to domains at scale. publicwww source-search finds every site carrying a given tag/key — the strongest SaaS-tenant and sibling-domain pivot:
  ```
  # publicwww: every site embedding the target's GTM container / Segment key / Intercom app id
  https://publicwww.com/websites/%22GTM-XXXXXXX%22/
  https://publicwww.com/websites/%22cdn.segment.com%2Fanalytics.js%2Fv1%2F<write-key>%22/
  ```
- **Passive DNS** (SecurityTrails, DNSDB/Farsight, CIRCL.lu, WhoisXML): resolve current CNAMEs to SaaS hosts to prove tenancy (`api.<target>.com` → `<tenant>.okta.com`). For the *time-series/historical* angle (when a tenant was added/dropped) use `asset_discovery_historical_deep` — this file uses pDNS only for current-tenancy confirmation.
- **Security ratings** (SecurityScorecard, BitSight, UpGuard): free/preview reports sometimes enumerate a target's known vendors and exposed services — a vendor list to confirm, not trust.
- **BGP.tools / PeeringDB**: ASN relationships and shared colocation infer self-hosted infra and provider ties (`bgp.tools/as/<asn>`).

**Gotcha**: correlate, don't trust — a fingerprinter or rating vendor's list is a lead; confirm each tenant directly with the per-platform probes above before recording it as in-scope surface.

## Tooling and Command Reference

- **`bbot`** — modular recon/OSINT; SaaS and cloud-tenant modules (`bbot -t <domain> -f subdomain-enum cloud-enum -m ...`).
- **`spiderfoot`** — 200+ OSINT modules incl. SaaS/tenant correlation; run headless (`sf.py -s <domain> -t ...`).
- **`theHarvester`** — emails, subdomains, hosts across public sources (`theHarvester -d <domain> -b all`).
- **`amass intel`** — org-level OSINT and ASN/domain relationships (`amass intel -org "<Org>"`, `amass intel -asn <asn>`).
- **`AADInternals`** (PowerShell) — Entra tenant recon unauthenticated (`Invoke-AADIntReconAsOutsider -DomainName <domain>`); **`roadrecon`** (roadtools) — Entra enumeration from a token.
- **`gh`** CLI — GitHub org/member/repo/code enumeration (above); **Sourcegraph** (`sourcegraph.com/search`) — structural code search across public GitHub.
- **Google/GitHub dorking** — `site:<tenant>.atlassian.net`, `site:*.slack.com <org>`, GitHub code search `org:<org> "okta.com"`.
- **Maltego** — commercial OSINT graphing (GUI; prefer the scriptable tools in-sandbox).

Install any tool not present at runtime. Never exfiltrate or use a discovered live credential (Slack/OpenAI/ESP token) — record its presence, location, and scope only.

## What Deep SaaS/IdP Recon Completeness Looks Like

SaaS/IdP recon is done only when:

- The target's identity provider(s) are identified (Okta / Auth0 / Entra / Google Workspace / Ping / other) and the federation topology mapped (managed vs federated, AD FS host)
- Every SaaS platform the target uses is catalogued — from analytics/marketing tags, SPF/DNS records, public docs and job posts, and SSO redirect hosts
- Per-platform tenant surface is enumerated (Slack workspace, Jira/Confluence tenant + anonymous access, GitHub org + members)
- Developer-platform surface is enumerated (GitHub/GitLab org, npm scope, container-registry namespaces, package-registry usernames)
- CI/CD platform correlation is established (public workflow logs, runner IPs)
- Marketing/analytics tag correlation has surfaced the sibling-domain set WHOIS misses
- The AI/ML footprint is discovered where applicable (model-provider orgs, LangSmith/W&B/MLflow tenants, HF org/Spaces, vector DBs, OpenAI-compatible proxies)

Only then scope hunters to SaaS-specific classes: Slack/Discord token and webhook abuse, Jira JQL/user-picker enumeration, Confluence RCE CVEs (fingerprint first), GitHub Actions supply-chain, Salesforce guest-user exposure, and unauthenticated ML/vector-DB endpoints.

## Pro Tips

1. IdP tenant enumeration is the fastest read of a target's identity architecture — `getuserrealm.srf` and `openid-configuration` map federation unauthenticated; start there.
2. Analytics/marketing tag correlation (one GA4/GTM id across domains) reveals sibling domains WHOIS and DNS will not connect — the highest-yield pivot.
3. SaaS tenant subdomains are almost always the org short name (`<company>.slack.com`, `<company>.atlassian.net`) — guess, then confirm; the sign-in page is public even for invite-only tenants.
4. Public Jira/Confluence with anonymous access is a routine internal-info leak — hit `/rest/api/2/project` and the user-picker before assuming it is locked down.
5. A GitHub org's public member list names employees LinkedIn enumeration misses; git history and made-public forks leak more than HEAD.
6. AI/ML observability tenants (LangSmith, W&B, MLflow, LangFuse) increasingly leak prompt/response logs and datasets — self-hosted MLflow/vector DBs are frequently auth-off.
7. Public npm scopes and container registries often expose more code (and baked-in secrets) than the org's GitHub; an unclaimed scope is a dependency-confusion lead.
8. Marketing-automation tenants (HubSpot, Marketo, Salesforce Community) frequently expose internal document links and over-permissioned guest data.
9. Vector-database endpoints (Pinecone/Qdrant/Weaviate) are the newest AI-app surface — a `200` on `/collections` or `/v1/meta` is unauthenticated embedding access, invertible back to source text.

## Summary

This deep sibling to `asset_discovery` maps the target's SaaS and identity-provider tenant surface: IdP federation, collaboration/ticketing/document platforms, developer and CI/CD platforms, marketing/analytics correlation, and the 2024-2026 AI/ML footprint (model providers, observability, inference hosting, vector DBs). It loads only in deep mode. Completeness means the IdP is mapped, every used SaaS platform is catalogued and tenant-enumerated, sibling domains are linked by tag correlation, and the AI/ML footprint is found — before SaaS-specific hunters are scoped. Companion deep siblings `asset_discovery_cloud_deep` (cloud runtime/edge) and `asset_discovery_historical_deep` (historical/OSINT) cover the adjacent scopes.
