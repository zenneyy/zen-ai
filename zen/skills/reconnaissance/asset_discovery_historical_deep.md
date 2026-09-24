---
name: asset-discovery-historical-deep
description: Historical, time-series, and OSINT-derived asset discovery. Loaded automatically by deep scan mode as a companion to asset_discovery.md. Covers certificate transparency time-series analysis, historical DNS mining, Wayback Machine depth, GitHub historical analysis, employee-linked infrastructure OSINT, BGP historical, WHOIS historical, acquisition/divestiture tracking, and shadow IT via certificate lifecycle.
sibling: asset_discovery
load_when: scan_mode == "deep"
---

# Asset Discovery — Historical / Time-Series / OSINT (Deep)

This is the deep sibling to `asset_discovery` for the time axis. The base file and the other two siblings map what the target *is right now*; this file maps what it *was*, what it leaks over time, and what a current-state sweep structurally cannot see: decommissioned-but-still-live hosts, subdomains that only ever appeared in a years-old certificate, endpoints removed from the site but preserved in an archive, secrets force-pushed out of a git branch, and infrastructure inherited through an acquisition and never re-secured.

It loads only in deep scan mode. Companion siblings cover the other axes: `asset_discovery_cloud_deep` (cloud runtime/edge — do not duplicate its infrastructure content) and `asset_discovery_saas_deep` (SaaS/IdP tenant — do not duplicate its current-org enumeration). This file owns the historical/OSINT layer; where those files touch time (saas_deep's passive-DNS enrichment, the base file's CT pivot), they point here.

The governing idea: append-only and archival systems never forget. A CT log keeps every SAN forever; the Wayback Machine keeps removed pages; passive-DNS keeps retired records; GitHub retains force-pushed commits until garbage collection. Every one of these is a lead to surface the org believes it retired. Prefer the free, queryable sources (crt.sh, Wayback CDX, RIPEstat, GH Archive) that a hunter can test on any domain; note where a source needs a paid key.

Techniques and tool status verified 2026-09-13; several sources changed recently (Google Cache retired, GHTorrent frozen, BGPMon folded into Cisco) — those corrections are called out inline.

## Certificate Transparency Deep Analysis

The base file uses CT for the current SAN pivot. Here the value is the *time series*: issuance and expiry dates reveal pre-provisioning, abandonment, and migration — surface that current DNS no longer shows.

### Time-series issuance analysis

crt.sh returns per-cert timestamps; sort by them to see the org's provisioning timeline.

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' \
  | jq -r '.[] | [.not_before, .not_after, .name_value] | @tsv' | sort -u | sort
# certspotter API (token raises rate limit): every issuance incl. subdomains
curl -s 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names' \
  | jq -r '.[] | [.not_before, (.dns_names|join(","))] | @tsv'
```

**Confirm**: a cert whose `not_before` predates any public mention of a service is **pre-provisioning** — an upcoming launch, discoverable before it goes live. A cert renewed on schedule but whose host no longer resolves/serves is **abandonment** — forgotten infrastructure.

**Gotcha**: `name_value` in crt.sh carries every SAN on the cert — a single cert routinely lists internal/staging hostnames never in DNS; extract all of them, not just the queried name.

### Cross-CT-log correlation

No single log has every cert. crt.sh aggregates most, but cross-reference for completeness. Google operates **Argon** (US) and **Xenon** (EU) logs, sharded per year (`argon2026h1/h2`, `xenon2026h1/h2` — verified current 2026-09; older Google shards are read-only but still queryable); other operators: Cloudflare **Nimbus**, Sectigo **Sabre/Mammoth**, DigiCert, Let's Encrypt **Oak**.

```bash
# certspotter and Censys see certs crt.sh may lag on
curl -s 'https://api.certspotter.com/v1/issuances?domain=example.com&include_subdomains=true&expand=dns_names' | jq -r '.[].dns_names[]' | sort -u
```

**Gotcha**: a cert can appear in one log and not another; if a subdomain shows in certspotter but not crt.sh (or vice versa), it is still real — union the sources.

### Continuous CT monitoring

Historical CT is a snapshot; during a longer engagement, subscribe to the CT firehose to catch certs the target issues *while you test* — new subdomains appear here minutes after issuance, before DNS or the app references them.

```bash
# certstream (calidog) streams every new CT entry; filter for the target
certstream --json | jq -r 'select(.data.leaf_cert.all_domains[]?|test("example\\.com$")) | .data.leaf_cert.all_domains[]' 2>/dev/null
```

**Gotcha**: a freshly-issued cert for `<new-service>.example.com` seen on the firehose is pre-launch surface — the earliest possible discovery, ahead of the passive-DNS and archive sources; watch the stream across the engagement, not just once.

### Wildcard and SAN mining

A wildcard cert (`*.corp.example.com`) hides the specific hosts, but **non-wildcard** certs list them explicitly as SANs. Mine every issued cert's SAN set — the hosts an org forgot are in an old multi-SAN cert.

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].name_value' | tr '\n' '\n' | sed 's/^\*\.//' | sort -u
```

**Gotcha**: wildcards tell you a naming scheme exists (`*.internal.example.com`) even when individual hosts resolve privately — seed targeted guesses from the wildcard's base.

### Precertificate analysis

CT logs contain **precertificates** — SCT-stamped and logged *before* the final cert issues — an even earlier discovery window. crt.sh marks precerts distinctly.

**Gotcha**: treat a precert as a live lead; the service usually stands up days later on that exact name, so a precert for `payments.example.com` is advance notice of a payments service.

### Issuance-timing correlation

Certs clustered around known product-launch or event dates reveal upcoming services before they are announced.

```bash
curl -s 'https://crt.sh/?q=%25.example.com&output=json' | jq -r '.[].not_before' | cut -c1-7 | sort | uniq -c
```

**Gotcha**: a spike in issuance in a month correlates to a launch/migration — line the timeline up against press releases and job posts to predict what is coming online.

### EV vs DV patterns

An Extended-Validation cert on an unusual subdomain flags a high-value system (payment, admin, partner portal) the org paid extra to strongly identify — prioritize it.

**Gotcha**: most modern certs are DV (Let's Encrypt); an EV or OV cert on a non-obvious host is a deliberate signal that the host matters — worth ranking above the DV crowd.

### Cert lifecycle abandonment

A still-valid cert with no live service behind it is forgotten infrastructure — a prime dangling-DNS/takeover lead (hand to `subdomain_takeover`).

**Gotcha**: auto-renewal (Let's Encrypt) keeps a cert valid long after the service died — a currently-valid cert is *not* evidence the host is live; confirm resolution/response separately.

### Cross-issuer transitions

An issuer change over time (Let's Encrypt → Sectigo → DigiCert) usually marks an infrastructure migration; the *old* issuer's certs point at the pre-migration surface, frequently left running.

```bash
curl -s 'https://crt.sh/?q=example.com&output=json' | jq -r '.[] | [.not_before, .issuer_name] | @tsv' | sort -u | sort
```

**Gotcha**: mine both the current and previous issuer's certs — a migration leaves the old CDN/origin serving stale content on the pre-migration hostnames.

## Historical DNS Analysis

Passive DNS is the canonical owner of the "what did this resolve to before" question (saas_deep and the base file defer here). No provider sees every query — cross-reference.

### Passive-DNS provider comparison

- **SecurityTrails** (~5+ yr history; API key): `https://api.securitytrails.com/v1/history/<domain>/dns/{a,mx,ns,txt}`.
- **DNSDB / Farsight** (~10+ yr; paid): `dnsdbq -r <domain>/ANY`.
- **CIRCL.lu pDNS** (free tier; auth): `https://www.circl.lu/pdns/query/<domain>`.
- **WhoisXML / VirusTotal** (2+ yr): VT `https://www.virustotal.com/api/v3/domains/<domain>/resolutions`.

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/a" -H "APIKEY: $ST_KEY" \
  | jq -r '.records[] | [.first_seen, .last_seen, (.values[].ip)] | @tsv'
```

**Gotcha**: providers see different resolvers' traffic — a record missing from one appears in another; union them before concluding a host never existed.

### MX-record history

MX changes date email-platform migrations (Google ↔ Microsoft ↔ ESP); each old platform is a lingering tenant (cross to `saas_deep`).

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/mx" -H "APIKEY: $ST_KEY" | jq -r '.records[] | [.first_seen,.last_seen,(.values[].hostname)] | @tsv'
```

**Gotcha**: an old MX names a mail platform the org may still have a tenant on — enumerate that tenant even though current mail routes elsewhere.

### NS-record history

NS changes date DNS-provider migrations; old nameservers sometimes still answer stale records for edge-case queries (lame delegation).

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/ns" -H "APIKEY: $ST_KEY" | jq -r '.records[] | [.first_seen,(.values[].nameserver)] | @tsv'
```

**Gotcha**: query an old nameserver directly (`dig @old-ns example.com ANY`) — it may still serve records the current NS set dropped.

### TXT-record history

TXT accumulation (`v=spf1` includes, DKIM selectors, domain-verification tokens) is the full email- and SaaS-verification history, including retired senders still SPF-authorized and verification tokens for services since dropped.

```bash
curl -s "https://api.securitytrails.com/v1/history/example.com/dns/txt" -H "APIKEY: $ST_KEY" | jq -r '.records[].values[].value'
```

**Gotcha**: an SPF `include:` for a decommissioned ESP is both a spoofing surface and, if the include's zone was released, a takeover lead; old `*-site-verification` TXT tokens name every SaaS the org ever verified a domain to.

### DNSSEC history

The timing of DNSSEC adoption/abandonment; an abandoned deployment (DS left at the registrar after signing stopped) breaks resolution for validating resolvers.

**Gotcha**: an abandoned DNSSEC deployment is why a "dead" host is sometimes reachable only from non-validating resolver paths — test resolution from both a validating and non-validating resolver.

### CAA history

CAA-record changes reveal cert-issuance-policy shifts and usually coincide with an issuer migration (cross-ref the CT cross-issuer section).

**Gotcha**: a CAA change dates a cert-issuer migration precisely — line it up with the CT issuer timeline to find the pre-migration origin.

### Historical CNAME chains

Old CNAMEs pointing at now-dead SaaS/cloud targets are **takeover candidates by lineage** — even if the current record is clean, the historical one names a service the org used and may re-point to.

```bash
curl -s "https://api.securitytrails.com/v1/history/www.example.com/dns/cname" -H "APIKEY: $ST_KEY" | jq -r '.records[] | [.first_seen,.last_seen,(.values[].hostname)] | @tsv'
```

**Gotcha**: a historical CNAME to a since-deprovisioned SaaS host is a claimability lead even if the current record is clean — hand the old target to `subdomain_takeover` to check if it is now registrable.

### A-record history

Historical A records reveal hosting migrations; an IP that once hosted the target may still serve the old site.

```bash
curl -s "https://api.securitytrails.com/v1/history/www.example.com/dns/a" -H "APIKEY: $ST_KEY" | jq -r '.records[] | [.first_seen,.last_seen,(.values[].ip)] | @tsv'
curl -s -H 'Host: www.example.com' http://<historical-ip>/ | head   # stale VirtualHost check
```

**Gotcha**: probe a historical IP directly with the target's `Host:` header — a shared/misconfigured origin often still returns the old site (VirtualHost confusion), exposing content removed from the current host.

## Wayback Machine and Archive Deep Mining

Web archives preserve what the site removed. The Wayback CDX API is free and scriptable — the workhorse here.

### Timestamp-scoped URL discovery

```bash
# every archived URL for the domain in a date window, deduped
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey&from=20200101&to=20221231" | sort -u
gau --from 202001 --to 202212 example.com | sort -u
waymore -i example.com -mode U    # Wayback + CommonCrawl + URLScan + OTX + VirusTotal + more, in one pass
```

**Gotcha**: `waymore` (xnl-h4ck3r, maintained) pulls from Wayback, CommonCrawl, AlienVault OTX, URLScan, VirusTotal, GhostArchive and Intelligence X at once and can download the archived *responses* — the widest single-command historical URL sweep.

### JS bundle version diffing

Old archived JS bundles contain endpoints since removed from production. Diff an archived bundle against the current one:

```bash
ts=$(curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/app.js&output=text&fl=timestamp&limit=1")
curl -s "http://web.archive.org/web/${ts}id_/https://example.com/app.js" -o old.js
grep -rhoE "/(api|v[0-9]+|internal|admin|graphql)/[A-Za-z0-9_/.-]+" old.js | sort -u
```

**Gotcha**: the `id_` suffix on the Wayback URL returns the raw original (no Wayback toolbar injection) — essential for clean bundle diffing. Endpoints in the old bundle but absent from the current one are removed-but-often-still-live APIs.

### Historical screenshots

Wayback renders/screenshots capture admin panels and internal routes once linked from the marketing site but since delinked — visible only in the archived render, not in any URL list.

```bash
# browse the calendar of captures; the rendered snapshot shows what was linked then
# http://web.archive.org/web/2*/https://example.com/
```

**Gotcha**: a route reachable only through a since-removed nav link survives in the archived render — read the rendered page for links the current site no longer exposes.

### Content-differential archives

Diff the current site against a 6-12-month-old capture to recover removed blog posts, employee bios, and product pages (recon material: names, internal system references, deprecated features).

```bash
comm -23 <(curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&collapse=urlkey" | sort -u) <(sort current_urls.txt)
```

**Gotcha**: a 404-now / archived-then URL is exactly where removed content lives — fetch the archived copy, not the live 404.

### Archived API responses

Wayback sometimes captured JSON/XML endpoints directly — revealing API structure, fields, and error formats since changed.

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=api.example.com*&output=text&fl=timestamp,original&filter=mimetype:application/json&collapse=urlkey"
```

**Gotcha**: an archived API response documents the endpoint's historical schema (fields/params since removed or renamed) — a map of the API's evolution the live endpoint won't give.

### archive.today

archive.ph / archive.is captures pages Wayback misses, including JS-heavy renders and pages behind soft-blocks. No clean bulk API — query per URL `https://archive.ph/https://example.com`.

**Gotcha**: archive.today often has the single capture of a page Wayback refused (robots-blocked or JS-only) — check it when Wayback has a gap.

### CommonCrawl

Petabyte web crawl, indexed per monthly snapshot; query the columnar/CDX index for the domain.

```bash
curl -s "https://index.commoncrawl.org/CC-MAIN-2024-33-index?url=example.com/*&output=json" | jq -r '.url' | sort -u
```

**Gotcha**: CommonCrawl reaches pages neither Wayback nor archive.today captured (its crawl seeds differ) — a third independent URL source; `waymore` queries it for you.

### URLScan.io

Public scans (submitted by anyone) with screenshots and the full DOM/request list at scan time.

```bash
curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1000" | jq -r '.results[].page.url' | sort -u
```

**Gotcha**: public URLScan results frequently expose internal URLs, redirect targets, and headers captured at scan time — search by `domain:` and by `page.url` substrings for subdomains never in DNS.

### Google Cache (retired)

**Google Cache is gone** — fully removed September 2024; the `cache:` operator no longer works and Google's "About this page" now links to the Wayback Machine instead. Do not attempt `cache:` queries; use Wayback / archive.today / CommonCrawl / URLScan.

**Gotcha**: older tooling and guides still reference `cache:` — it silently returns nothing now, so a "no results" is not a signal about the target.

## GitHub Historical Analysis

The org's *current* GitHub surface is in `saas_deep`. Here the target is what GitHub retained after deletion: dangling commits, force-pushed secrets, deleted repos, and the event stream.

### Force-pushed and dangling commits (CFOR)

A force-push rewrites branch history, but the pre-force-push commit is **not** immediately deleted — it stays reachable by SHA (and across the fork network) until GitHub garbage-collects, often indefinitely for forked repos. The push event retains the old SHA.

```bash
# push events retain before/after SHAs; a force-push shows a 'before' not in current history
gh api "/repos/<owner>/<repo>/events?per_page=100" --jq '.[] | select(.type=="PushEvent") | {before:.payload.before, head:.payload.head, ref:.payload.ref}'
# fetch a dangling commit directly by SHA — still served until GC
gh api "/repos/<owner>/<repo>/commits/<dangling-sha>" 2>/dev/null | jq '.files[].filename'
```

**Gotcha**: this is the "oops commit" class (Truffle Security research, 2024) — secrets removed by a follow-up force-push remain retrievable by the old SHA; GH Archive (below) and the Events API preserve those SHAs long after the branch looks clean.

### Deleted repos via Wayback

Deleted repos are frequently preserved in Wayback captures of the `github.com/<org>/<repo>` URL, the file tree, and `raw.githubusercontent.com` file URLs.

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=github.com/<org>/<deleted-repo>*&output=text&fl=original&collapse=urlkey"
curl -s "http://web.archive.org/cdx/search/cdx?url=raw.githubusercontent.com/<org>/<repo>*&output=text&fl=original&collapse=urlkey"
```

**Gotcha**: even when the repo 404s now, the archived raw-file URLs return the file contents — fetch those, and check GH Archive (below) for the events that reference the deleted repo.

### Deleted branches and hidden PR refs

`git ls-remote` exposes every ref, including `refs/pull/<n>/head` — PR commits survive branch deletion and closed/unmerged PRs.

```bash
git ls-remote https://github.com/<owner>/<repo> 'refs/*' | grep -E 'pull/|refs/heads'
git fetch origin 'refs/pull/*/head:refs/remotes/pr/*'   # then scan the fetched PR history
```

**Gotcha**: `refs/pull/*/head` gives code from PRs that were never merged (and from deleted branches) — a common home for the change that was "reverted" but never scrubbed; fetch and secret-scan it with the history tools below.

### GH Archive (BigQuery) and event history

**GHTorrent is discontinued** (data frozen ~2019 — use only for pre-2019 lineage). The live successor is **GH Archive** (`gharchive.org`): every public GitHub event since 2011, hourly, and mirrored to BigQuery `githubarchive.day.*` / `.month.*`.

```sql
-- BigQuery: all target-org activity in a day (adjust date; check mirror recency, some reports of lag)
SELECT created_at, type, actor.login, repo.name
FROM `githubarchive.day.20240115`
WHERE repo.name LIKE '<org>/%' OR actor.login IN ('<employee1>','<employee2>')
```

**Gotcha**: GH Archive captures events (pushes, forks, deletes, gollum/wiki edits) even for repos later made private or deleted — it is the historical record when the live repo is gone; verify the BigQuery mirror's recency (occasional lag reported) or use the raw hourly `.json.gz` from gharchive.org.

### Employee personal repos and gists

Employees' *personal* repos and public **gists** routinely carry work snippets, config, and credentials. Correlate employees (next section) → their accounts → their public content.

```bash
gh api "/users/<employee>/gists" --jq '.[].files | keys[]' 2>/dev/null
gh api "/users/<employee>/repos?per_page=100" --jq '.[] | select(.fork==false) | .full_name' 2>/dev/null
```

**Gotcha**: search employee accounts, not just the org — a developer's personal `dotfiles`/`scripts` repo or a "quick test" gist is a frequent home for a work API key or an internal hostname.

### GitHub Discussions

Public Discussions on the org's repos (and employees' participation elsewhere) hold design debate, internal URLs, and troubleshooting detail.

```bash
gh api graphql -f query='{repository(owner:"<org>",name:"<repo>"){discussions(first:50){nodes{title,url}}}}' 2>/dev/null
```

**Gotcha**: Discussions are indexed and public but easy to forget — they often contain the "why" and the internal context that issues/PRs omit.

### Time-scoped and path-based code search

GitHub Code Search operators find work-related content across the org and employee accounts, scoped by path/filename.

```bash
gh search code "org:<org> path:**/.env" 2>/dev/null
gh search code "org:<org> filename:.npmrc _auth" 2>/dev/null
gh search code "\"@<org>.com\" filename:.aws/credentials" 2>/dev/null
```

**Gotcha**: pair path/filename operators (`filename:.pgpass`, `path:**/config/secrets*`) with the org name and the employee-email domain — the highest-yield secret-discovery queries; `git-hound` runs this class across all of GitHub.

### Sourcegraph cross-repo search

`sourcegraph.com` indexes public GitHub and supports structural and regex search across all of it at once — find the org's code and secrets by pattern regardless of which repo (or employee account) holds them.

```
# sourcegraph.com queries (web or `src search` CLI):
#   context:global "@example.com" file:\.env$
#   context:global repo:github\.com/<org>/.*  (\bAKIA[0-9A-Z]{16}\b OR internal\.example\.com)
```

**Gotcha**: Sourcegraph catches cross-repo patterns a per-repo search misses (a hostname reused across many small repos) and can search commit *diffs* on indexed repos — a wider net than `gh search code`.

### Historical secret scanning of git history

Current-tree scanning misses secrets removed in a later commit. Scan the **full history**:

```bash
trufflehog git file://. --results=verified,unknown 2>/dev/null      # walks all commits
gitleaks detect --source . --log-opts="--all" -f json               # every ref, full history
noseyparker scan --git-history=full .                               # Praetorian, maintained
```

**Gotcha**: `--log-opts="--all"` / `--git-history=full` are what make these scan deleted-from-HEAD-but-in-history secrets; `git-hound` (tillson, maintained) runs the same class of search across *all* of GitHub, not just a known repo.

## Employee-Linked Infrastructure via OSINT

People leak infrastructure the org's DNS never will — internal tool names, system names, upcoming tech, and personal accounts that touch work systems.

### LinkedIn and employee enumeration

Company page → employee list → names/roles. Tools: `linkedin2username`, `crosslinked` (generate username permutations from scraped names — feed to the IdP enumeration in `saas_deep`).

```bash
crosslinked -f '{first}.{last}@example.com' "Example Inc"   # name -> email/username candidates
```

**Gotcha**: an employee's *other/previous* companies on LinkedIn reveal integration and acquisition surface; roles like "SRE", "Platform", "Data" name the internal stack in their titles and posts.

### GitHub-account correlation

Map employees to GitHub accounts via commit author emails in the org's repos and via LinkedIn cross-reference:

```bash
git log --all --format='%an <%ae>' | sort -u        # author emails on a cloned org repo
gh api "/repos/<org>/<repo>/contributors" --jq '.[].login'
```

**Gotcha**: a `@example.com` commit email ties a GitHub account to the org even when the profile hides employer; that account's personal repos are then in scope for the secret scan above.

### Personal blogs and resumes

Employee personal blogs and posted resumes name specific internal systems and technologies ("migrated our Kafka cluster to…", "built the internal billing service on…").

**Gotcha**: a resume/CV lists internal system and tool names by their real internal names — the vocabulary to grep for in bundles, repos, and archived content.

### Conference talks

Talks (SpeakerDeck, YouTube, slide decks, meetup recordings) diagram internal architecture. Search the org name + "architecture" / "platform" / "scaling".

```bash
# speakerdeck / youtube search seeds
# "example inc" site:speakerdeck.com ; "how we built" "Example" architecture
```

**Gotcha**: an architecture talk names internal service names, data stores, and vendors on the slides — often the clearest single map of the internal stack.

### Job postings

Current and **archived** postings (careers page via Wayback, LinkedIn/Indeed) enumerate the stack; archived ones are frequently more specific than the current sanitized versions and reveal tech *before* it is live.

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/careers*&output=text&fl=original&collapse=urlkey"
```

**Gotcha**: a post requiring "experience with <specific product/version>" is a pre-announcement of that technology in the environment — mine archived postings for stack detail scrubbed from current ones.

### Meetup and Eventbrite

Meetups/events the org sponsors or hosts reveal team locations, office addresses, and the tech the team gathers around.

**Gotcha**: a sponsored meetup's topic (a specific database, framework, or cloud) is a stack signal; RSVP/attendee lists sometimes name employees not yet found elsewhere.

### Employee personal service accounts

Employees' Twitter/X, Mastodon, and dev-community profiles reveal technology preferences, frustrations ("fighting our <product> upgrade"), and sometimes screenshots of internal tooling.

**Gotcha**: a screenshot in a social post frequently leaks an internal hostname, dashboard, or ticket id in the browser chrome — mine images, not just text.

### Open-source contributions

An employee's PRs/issues to a specific tool's repo (found via their GitHub account) are strong evidence that tool runs internally.

```bash
gh api "/users/<employee>/events/public" --jq '.[] | select(.type=="PullRequestEvent") | .repo.name' 2>/dev/null | sort -u
```

**Gotcha**: pair the tool with the version the employee discusses/patches for a version-fingerprinted internal target — a contribution to a niche project is rarely unrelated to the day job.

## BGP Historical Analysis

Routing history reveals when IP space came online and how the org's network relationships changed.

### RIPEstat and BGPStream

**RIPEstat** (RIPE NCC, free API, RIS-collector data) is the workhorse; **BGPStream** (CAIDA) for programmatic live+historical analysis. **BGPMon's** free public service is legacy (folded into Cisco after the OpenDNS acquisition) — use RIPEstat / bgp.tools / Cloudflare Radar instead.

```bash
curl -s "https://stat.ripe.net/data/routing-history/data.json?resource=AS<asn>" | jq -r '.data.by_origin[].prefixes[] | [.prefix, .timelines[0].starttime] | @tsv'
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<asn>" | jq -r '.data.prefixes[].prefix'
```

**Confirm**: a prefix's first-seen time in `routing-history` dates when the org brought that range online — new ranges are candidate fresh surface; withdrawn prefixes are decommissioned space that may still host stragglers.

### ASN relationship history

Upstream/peer changes over time (`bgp.tools/as/<asn>`, RIPEstat `asn-neighbours-history`) reveal provider migrations — an old upstream points at the pre-migration hosting.

```bash
curl -s "https://stat.ripe.net/data/asn-neighbours/data.json?resource=AS<asn>" | jq -r '.data.neighbours[] | [.asn,.type] | @tsv'
```

**Gotcha**: a dropped upstream marks when the org left a hosting provider — surface on that provider's ranges is a decommissioning lead.

### Route anomaly / hijack detection

BGPStream (CAIDA) and Cloudflare Radar surface route anomalies and hijacks affecting the target's prefixes.

**Gotcha**: hijack events are attribution/monitoring signals, not usually target surface — note them but don't treat a transient anomaly as discoverable assets.

### Facility and colocation history

PeeringDB entries (current and archived) reveal data-center/facility presence and moves; a facility change dates an infrastructure migration.

**Gotcha**: a PeeringDB facility the org left may still host stragglers on the old ranges announced from there.

### CIDR reallocation

IANA/RIR transfer records show IP-block reallocation between orgs over time.

**Gotcha**: a range transferred *away* from the target may still be referenced by the target's old configs/CNAMEs; one transferred *to* the target arrives with the previous owner's stale DNS pointing into it — check both directions.

## WHOIS Historical

### Registration-record history

Historical WHOIS (WhoisXML, DomainTools) shows registrar and registration-date changes over the domain's life.

```bash
curl -s "https://whois-history.whoisxmlapi.com/api/v1?apiKey=$WX&domainName=example.com&mode=purchase" | jq '.records[] | {createdDate,updatedDate,registrarName}'
```

**Gotcha**: a registrar change often accompanies an ownership or hosting transfer — a date to line up against the CT/DNS/BGP timelines.

### Ownership-change tracking

Registrant-org and registrant-contact changes mark inherited or abandoned infrastructure; a registrant email is a pivot to other domains the same contact registered (reverse-WHOIS).

```bash
# reverse WHOIS: other domains registered by the same email/org
curl -s "https://reverse-whois.whoisxmlapi.com/api/v2?apiKey=$WX&searchType=current&mode=purchase&basicSearchTerms[include][]=<registrant-email>"
```

**Gotcha**: reverse-WHOIS on a registrant email/org surfaces sibling domains WHOIS-privacy and DNS won't connect — a strong pivot for acquisition-era and personal-registration assets.

### Nameserver history

Old nameservers listed in historical WHOIS occasionally still answer for the zone (lame delegation) and return stale records.

**Gotcha**: query an old nameserver directly (`dig @<old-ns> example.com ANY`) — a lame-delegated NS sometimes serves records the current set dropped, exposing hosts that vanished from the live zone.

## Company Acquisition and Divestiture Tracking

Acquisitions bolt on infrastructure that is least-secured during integration; divestitures leave integrations behind.

### SEC filings

For public targets, 8-K filings disclose material acquisitions; 10-K subsidiary exhibits (Exhibit 21) list legal entities.

```bash
# EDGAR full-text search API (JSON)
curl -s 'https://efts.sec.gov/LATEST/search-index?q=%22acquisition%22&forms=8-K&dateRange=custom&startdt=2022-01-01&enddt=2026-01-01&entityName=<name>' 2>/dev/null
# company filings index
curl -s 'https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&company=<name>&type=8-K&output=atom'
```

**Gotcha**: the 10-K Exhibit 21 "subsidiaries of the registrant" is a literal list of legal entity names — each is a brand/domain seed for the base file's CT/DNS enumeration.

### LinkedIn / Crunchbase / Wikipedia tracking

"Acquired by" edges on LinkedIn company pages, Crunchbase acquisition records, and Wikipedia's acquisition-history tables give the timeline and the brand names for private targets EDGAR won't cover.

**Gotcha**: an acquisition announced but "integration ongoing" is the window when the subsidiary's infra is least-secured — prioritize recently-announced ones.

### Historical brand-name enumeration

The target's previous brand names, product names, and spin-offs each have their own domain footprint, frequently still under the target's control.

**Gotcha**: former names rarely appear in current-brand DNS/CT — enumerate each *former* name independently through the base file; acquisition-era and rebrand-era domains are a top source of forgotten, still-live hosts.

### Divested product enumeration

Products the target *sold* to another company may retain integrations (webhooks, SSO callbacks, API keys, DNS delegations) pointing back at the target — and the target's records may still point at the divested product.

**Gotcha**: divestiture leaves bidirectional stale trust — check both the target's records for the divested brand and the divested brand's records for the target.

### Post-acquisition integration surface

Newly-acquired subsidiary infrastructure mid-migration mixes the two orgs' controls, sets up temporary trust (federation, VPN, shared CI), and exposes migration tooling.

**Gotcha**: the migration window is the softest surface — temporary trust relationships (a federation set up "just for the migration") and migration jump-hosts are frequently left in place; cross to `subdomain_takeover` and `infrastructure_lifecycle` for lapsed-domain claims among the acquired assets.

## Domain Squatting and Typosquat Detection

Lookalike domains are phishing surface against the target and, when the target itself squatted defensively, extra owned assets.

```bash
dnstwist --registered --format json example.com | jq -r '.[] | [.domain, (.dns_a[0] // "")] | @tsv'
urlcrazy -f csv example.com
```

### Permutation engines

`dnstwist`, `dnstwister`, and `urlcrazy` generate lookalikes (character swap/omission/insertion, bitsquatting, TLD swap) and report which resolve, their A/MX, and (dnstwist) fuzzy-hash similarity to the real site.

```bash
dnstwist --registered --mxcheck --format json example.com | jq -r '.[] | [.domain, .fuzzer, (.dns_a[0]//"")] | @tsv'
```

**Gotcha**: `--mxcheck` flags squats with MX records — those are set up to *receive* mail (credential/phishing harvesting), a higher-priority finding than a parked squat.

### IDN homograph

Punycode (`xn--`) lookalikes substitute visually-identical Unicode (Cyrillic `а` for Latin `a`). Permutation engines with homoglyph fuzzers surface them.

```bash
dnstwist --registered example.com | grep 'xn--'
```

**Gotcha**: a registered homograph resolving anywhere is almost never benign — it exists to deceive; distinguish it from the target's own defensive punycode registration by where it points.

### Combosquatting

`<target>-support.com`, `<target>secure.com`, `<target>login.com`, `<target>-hr.com` — the semantic-prefix/suffix patterns permutation engines miss. Generate from a wordlist of security/support/login/HR terms crossed with the brand.

**Gotcha**: combosquats are the phishing pattern for credential-harvest against employees — check MX and any hosted login page; report as attacker infrastructure.

### Historical squat detection

Squats registered *before* the target's own registration (from historical WHOIS) reveal early copycats; a squat whose registration predates the brand launch is often a domainer or a competitor.

**Gotcha**: separate attacker squats (phishing surface — report as such) from the target's own **defensive** registrations (owned assets, often parked and forgotten, occasionally still running an old redirect/service). A lookalike resolving to the target's own infra is a defensive registration — an asset, not a threat.

## Metadata Leakage in Documents

Public documents carry authoring metadata that names internal users, software, and paths.

```bash
# harvest the org's public docs, then read metadata
for f in $(curl -s "http://web.archive.org/cdx/search/cdx?url=example.com*&output=text&fl=original&filter=original:.*\.(pdf|docx|xlsx|pptx)$&collapse=urlkey"); do
  curl -s "$f" -o /tmp/d && exiftool -a -u -g1 /tmp/d 2>/dev/null | grep -iE 'author|creator|producer|company|last.?modified|template|comment'; done
```

### PDF metadata

`exiftool` reveals authoring software/version, internal usernames, and sometimes internal file paths in the `Creator`/`Producer` fields and embedded XMP.

```bash
exiftool -a -u -g1 report.pdf | grep -iE 'author|creator|producer|title|company|create.?date'
```

**Gotcha**: an internal username in `Author`/`Creator` feeds the IdP username-enumeration in `saas_deep`; a `Producer` string names the exact software+version (a version-fingerprint lead).

### Office document metadata (DOCX/PPTX/XLSX)

Office Open XML files are zip archives — `docProps/core.xml` and `app.xml` hold author, company, template origin, revision count, and total-edit-time.

```bash
unzip -p deck.pptx docProps/core.xml docProps/app.xml 2>/dev/null | grep -oE '<(dc:creator|Company|Template|cp:lastModifiedBy)[^<]*'
exiftool -a -u -g1 deck.pptx | grep -iE 'creator|company|template|last.?modified'
```

**Gotcha**: `Template` in `app.xml` frequently contains an internal UNC path (`\\fileserver\templates\...`) that names an internal host; `lastModifiedBy` names another employee.

### Image EXIF

Photos on marketing/careers/press pages carry GPS coordinates (office locations), camera/device, software, and embedded thumbnails (which may differ from the shown image).

```bash
exiftool -a -u -g1 -gps:all photo.jpg | grep -iE 'gps|make|model|software|serial'
```

**Gotcha**: GPS on a "team photo" geolocates an office; a camera serial links photos across sites to one device/owner.

### Code-repository metadata

Git commit signatures and author dates (from the history scan above) reveal work patterns, timezones, and the real-name↔email↔GitHub-account mapping used in the employee-OSINT section.

**Gotcha**: commit timezones and cadence profile the team's location and working hours — useful for timing and for correlating anonymous contributions to known employees.

### API-response-header history

Response headers change over time; Wayback preserves them. Old `X-Powered-By` / `Server` / `X-AspNet-Version` banners recovered from archived captures fingerprint the *historical* stack — the version that may still run on an un-migrated host.

```bash
curl -s "http://web.archive.org/web/2021id_/https://example.com/" -D - -o /dev/null | grep -iE '^(server|x-powered-by|x-aspnet|x-generator):'
```

**Gotcha**: a header banner removed from the current site is often still present on a forgotten host — the archived value tells you what to look for.

### HAR files

`.har` (HTTP Archive) files shared publicly in support tickets, bug reports, and gists capture full request/response history — headers, cookies, and tokens included.

```bash
gh search code 'org:<org> extension:har' 2>/dev/null
grep -rhoE '"(Authorization|Cookie|x-api-key)"[^}]*' *.har 2>/dev/null | sed 's/\(......\).*/\1…[redacted]/'
```

**Gotcha**: a `.har` almost always contains live session tokens and auth headers from when it was captured — treat any public `.har` from or about the target as a credential exposure.

## Historical Bug-Bounty Scope Analysis

A program's *past* scope names assets the org acknowledged owning — including subsidiaries later dropped from scope but still live.

### Program-scope history

HackerOne/Bugcrowd/Intigriti program pages list in-scope assets; Wayback captures of the program page show scope over time.

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=hackerone.com/<program>&output=text&fl=timestamp&collapse=digest"
```

**Gotcha**: the *current* scope is a curated list of assets the org acknowledges owning — a free, authoritative asset inventory to seed enumeration from.

### security.txt history

`/.well-known/security.txt` names contacts, policy, and sometimes scope; its Wayback history shows when it changed.

```bash
curl -s "http://web.archive.org/cdx/search/cdx?url=example.com/.well-known/security.txt&output=text&fl=timestamp,original&collapse=digest"
```

**Gotcha**: an old `security.txt` may reference a bug-bounty platform or contact domain since changed — a lead to a former program and its former scope.

### Scope diffs

Diff old vs current program scope: an asset later *removed* from scope frequently still exists as a forgotten subsidiary.

**Gotcha**: removed-from-scope ≠ decommissioned — it usually means "we stopped watching it," which is exactly the surface worth checking.

## Advanced Favicon and JARM Historical Clustering

The base file uses favicon-hash and JARM for current clustering. Across *time*, they group infrastructure that shares no cert and no DNS.

### Favicon-hash historical correlation

The same favicon MurmurHash3 across hosts and across a time window is near-certain same-org.

```bash
shodan search 'http.favicon.hash:<mmh3>' --fields ip_str,port,hostnames
# date-bound the query to see when hosts carrying it appeared
shodan search 'http.favicon.hash:<mmh3> before:2024-06-01' --fields ip_str,hostnames
```

**Gotcha**: a favicon hash clusters an app across unrelated hostnames/IPs and across time — it survives DNS and WHOIS changes, so it groups infrastructure those miss.

### JARM historical fingerprints

A host's JARM changes when its TLS stack migrates (behind-CDN → direct hosting, or a load-balancer swap). A JARM shift dated against the CT issuer-change timeline confirms a migration and points at the pre-migration origin.

**Gotcha**: a JARM matching the target's known-origin JARM but on an unrelated IP is a direct origin behind a CDN — a WAF-bypass lead (cross to `asset_discovery_cloud_deep` for origin exposure).

### Cross-time infrastructure grouping

Hosts matching favicon **and** JARM across a 6-month window are almost certainly the same org even without WHOIS confirmation — combine both signals to attribute shadow infra.

**Gotcha**: favicon+JARM agreement is strong attribution but not proof of *current* ownership — confirm the host still resolves/serves before treating it as live surface.

## Threat-Intel Enrichment

Banner-history and reputation sources add the time dimension to a host.

### Shodan historical

`shodan host <ip> --history` returns every banner Shodan ever recorded for the IP — services since closed, firewalled, or changed.

```bash
shodan host <ip> --history | grep -iE 'timestamp|product|port|ssh|http'
# find the org's hosts by a historical banner/favicon (date-filter in the query)
shodan search 'http.favicon.hash:<mmh3> before:2024-01-01' --fields ip_str,port
```

**Gotcha**: a historical banner shows a service (old SSH version, a since-firewalled admin port) current scanning won't — the *past* exposure is a lead to what's still running but now filtered externally.

### Censys

Complementary host and certificate history (`search.censys.io`), with a richer cert dataset than Shodan. Query historical services and the cert-to-host mapping over time.

**Gotcha**: Censys often has the cert-linked host relationships Shodan lacks — cross-reference when a CT-discovered cert needs its serving IP history.

### ZoomEye and Fofa

Alternate global scanners; **Fofa** (Chinese) and **ZoomEye** frequently index hosts the Western scanners miss, especially infrastructure with Asia connectivity or that blocks Shodan/Censys ranges.

```bash
# Fofa dork (base64-encoded query via API) / ZoomEye search
# fofa: domain="example.com" ; zoomeye: hostname:example.com
```

**Gotcha**: a target that firewalls Shodan/Censys scan ranges may still be indexed by Fofa/ZoomEye — use them as a coverage check, not a primary.

### GreyNoise

`https://api.greynoise.io/v3/community/<ip>` classifies whether an IP is an internet-wide scanner or specific — for filtering noise from a discovered IP set and for attribution.

```bash
curl -s "https://api.greynoise.io/v3/community/<ip>" | jq '{noise,classification,name,last_seen}'
```

**Gotcha**: GreyNoise is for triage, not discovery — use it to drop opportunistic-scanner IPs from a candidate set so the remaining ones are worth investigating.

## Tooling and Command Reference

- **Wayback/archive mining**: `waybackurls`, `gau` (`--from`/`--to` YYYYMM), `waymore` (multi-source, downloads responses), `subjs` (JS URL extraction from archived pages).
- **Git history secrets**: `trufflehog git file://.`, `gitleaks detect --log-opts="--all"`, `noseyparker scan --git-history=full`, `git-hound` (GitHub-wide), `git-secrets --scan-history`.
- **GitHub historical**: `gh` CLI (Events API, `ls-remote`, code search), GH Archive on BigQuery (`githubarchive.day/month`), Sourcegraph for cross-repo/structural search.
- **Passive DNS**: SecurityTrails API, `dnsdbq` (DNSDB, licensed), CIRCL.lu (free tier), VirusTotal resolutions.
- **Typosquat**: `dnstwist --registered`, `urlcrazy`, `dnstwister`.
- **Metadata**: `exiftool -a -u -g1`.
- **BGP/WHOIS**: RIPEstat API, `bgpreader`/`pybgpstream` (BGPStream), WhoisXML history API.
- **OSINT frameworks**: `theHarvester`, `amass intel`, `bbot`, `spiderfoot`.

The highest-yield one-liners:

```bash
waymore -i example.com -mode U -oU urls.txt              # Wayback+CC+URLScan+OTX+VT+GhostArchive+IntelX
gau --from 202001 --to 202512 example.com | anew all_urls.txt
trufflehog git file://./repo --results=verified,unknown  # full-history secret scan
noseyparker scan --git-history=full ./repo && noseyparker report
dnstwist --registered --mxcheck --format csv example.com
theHarvester -d example.com -b bing,crtsh,certspotter,otx -l 500
amass intel -org "Example Inc" ; amass intel -asn <asn> -whois
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS<asn>" | jq -r '.data.prefixes[].prefix'
```

Never publish or register a discovered squat/lapsed domain to "confirm" it without explicit authorization and a containment plan (cross to `infrastructure_lifecycle`); never exfiltrate or use a secret recovered from git history — record its presence, commit SHA, and scope only.

## What Deep Historical Recon Completeness Looks Like

Historical recon is done only when:

- Passive-DNS history is catalogued across multiple providers (A/MX/NS/TXT/CNAME timelines), not a single source
- CT history is mined for both current and abandoned/pre-provisioned certs, cross-log, with SANs extracted
- The Wayback/CommonCrawl/URLScan archive set is diffed against current to surface removed endpoints and content
- GitHub historical is checked: dangling/force-pushed commits (Events API + GH Archive), deleted repos (Wayback), PR refs, and full-history secret scans
- Employee-linked infrastructure is catalogued (LinkedIn → GitHub accounts → personal repos/gists/talks/archived job posts)
- Acquisition/divestiture and former-brand history is mapped and each brand seeded back through the base file
- Squat/typosquat domains are enumerated (attacker vs defensive separated)
- BGP and WHOIS history is reviewed for range/ownership changes

Only then scope hunters to historical-artifact classes: forgotten/decommissioned subdomains and dangling DNS (`subdomain_takeover`, `infrastructure_lifecycle`), certificate-lifecycle takeovers, secrets recovered from git history, and stale-VirtualHost content on historical IPs.

## Pro Tips

1. Historical DNS routinely reveals infrastructure the org has forgotten it owns — cross-reference providers, because none sees every record.
2. Employee personal GitHub accounts and gists expose work credentials far more often than the org's own repos — correlate commit emails to find them.
3. Wayback screenshots and renders capture admin panels and internal routes the current site no longer links.
4. Acquired subsidiaries during the integration window are frequently the softest surface — track acquisitions and seed the new brands immediately.
5. Deleted GitHub repos are often still readable via Wayback captures of the `github.com/<org>/<repo>` URLs and raw file paths.
6. Personal blogs, conference talks, and archived job postings name internal tools and architecture — and job posts reveal tech before it is live.
7. Old certificate SANs live in CT logs forever — mine every issued cert's SANs regardless of whether the host resolves today.
8. Cross-reference the GitHub Events API / GH Archive with current history to find force-pushed ("oops") commits — the secret removed by a follow-up push is still retrievable by its old SHA.
9. Google Cache is gone (retired 2024) — reach for Wayback, archive.today, CommonCrawl, and URLScan instead.

## Summary

This deep sibling to `asset_discovery` works the time axis: CT time-series and abandonment, historical DNS, Wayback/CommonCrawl/URLScan depth, GitHub historical (dangling commits, deleted repos, git-history secrets), employee OSINT, BGP/WHOIS history, acquisition tracking, squat detection, document metadata, and cross-time favicon/JARM clustering — the surface a current-state sweep cannot see. It loads only in deep mode. Completeness means multi-source historical DNS + CT + archive diffing + GitHub history + employee/acquisition OSINT are all done before historical-artifact hunters are scoped. Companion deep siblings `asset_discovery_cloud_deep` (cloud runtime/edge) and `asset_discovery_saas_deep` (SaaS/IdP tenant) cover the present-state axes.
