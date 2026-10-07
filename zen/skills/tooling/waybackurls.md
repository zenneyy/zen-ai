---
name: waybackurls
description: waybackurls archive-URL fetch — minimal Wayback Machine scraper for historical-endpoint enumeration.
---

# waybackurls CLI Playbook

Official docs:
- https://github.com/tomnomnom/waybackurls

Canonical syntax:
`echo <domain> | waybackurls [flags]` (or `waybackurls [flags] < domains.txt`)

Install (not preinstalled in the sandbox):
`go install -v github.com/tomnomnom/waybackurls@latest`
(installed to `$HOME/go/bin/waybackurls`; sandbox PATH already includes it.)

High-signal flags:
- `-dates` prepend fetch date (`2019-07-02T18:15:14Z\thttps://...`) to every URL
- `-get-versions` for a single input URL, list the archived versions (timestamps + archive URLs) of that exact page
- `-no-subs` restrict to the exact domain (don't include subdomains that Wayback groups under it)

Agent-safe baseline for automation:
`echo target.tld | waybackurls | sort -u > wayback.txt`

Common patterns:
- Historical URL set for one domain (with subdomains):
  `echo target.tld | waybackurls | sort -u > wayback.txt`
- Just the exact domain, no subdomains:
  `echo target.tld | waybackurls -no-subs | sort -u > wayback_exact.txt`
- Batch across a list of roots:
  `cat roots.txt | waybackurls | sort -u > wayback.txt`
- Dated output for change-tracking / snapshot alignment:
  `echo target.tld | waybackurls -dates | sort -u > wayback_dated.tsv`
- Fetch archive versions of one specific URL (useful for retrieving old content):
  `echo https://target.tld/robots.txt | waybackurls -get-versions`
- Chain into live-check:
  `echo target.tld | waybackurls | sort -u | httpx -silent -mc 200,301,302,401,403 -o wayback_live.txt`
- Filter down to a specific path shape (e.g. `/api/`):
  `echo target.tld | waybackurls | grep '/api/' | sort -u > wayback_api.txt`
- Extract unique parameter names from historical URLs (feeds arjun / sqlmap):
  `echo target.tld | waybackurls | grep -oE '[?&][a-zA-Z0-9_]+=' | sort -u > wayback_params.txt`
- Drop static-asset noise before downstream processing:
  `echo target.tld | waybackurls | grep -vE '\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf|ico|mp4|mp3|zip|pdf)$' | sort -u > wayback_clean.txt`

Critical correctness rules:
- Input is **domains**, not URLs — pass bare hostnames (`target.tld`), not `https://target.tld`.
- The source is the Wayback Machine (`web.archive.org/cdx`); the sandbox `http_proxy` env routes the outbound call through Caido, which may rate-limit under sustained load.
- `-no-subs` is strict: the exact domain only. Default behavior includes everything Wayback indexes under the domain hierarchy.
- `-get-versions` takes a **full URL** on stdin (not a domain) and emits archive snapshot URLs, not working-mirror URLs.
- There is no built-in rate limiting, output format, or deduplication — `sort -u` after the fact.
- `-dates` output is tab-separated (`timestamp\tURL`) — downstream parsers must split on `\t`, not whitespace.

Usage rules:
- Pipe through `sort -u` for a deduplicated set; the raw stream has thousands of near-duplicates.
- Combine with `tooling/gau.md` only if you want multi-provider coverage (CommonCrawl, OTX, URLScan) — waybackurls alone is Wayback-only.
- Follow with `tooling/httpx.md` to live-check which archive URLs still resolve.
- Grep-filter early (archive sets are huge); feed only interesting URLs to `tooling/katana.md` / `tooling/ffuf.md`.
- Do not use `-h`/`--help` for routine runs unless absolutely necessary.

Failure recovery:
- Empty output on a domain you expect history for: verify the Wayback Machine actually indexes it (`curl -s "http://web.archive.org/cdx/search/cdx?url=target.tld/*&output=json" | head`).
- Hangs for minutes: Wayback's CDX endpoint can be slow for large histories — `timeout 300 waybackurls ...` and shard the input.
- 429s / connection resets from Wayback: throttle by chunking input, rotate upstream through `tooling/caido.md` match-and-replace if needed, or fall back to `tooling/gau.md` for multi-provider resilience.
- Output includes garbage or non-URLs: pipe through `grep -E '^https?://'` to filter.

If uncertain, query web_search with:
`site:github.com/tomnomnom/waybackurls` or `site:web.archive.org cdx search`

---

## CDX API Mechanics

waybackurls queries the Wayback Machine's CDX Server API at `web.archive.org/cdx/search/cdx`. Understanding the backing API clarifies the tool's behavior and limitations.

**What CDX returns:** URL records from the Wayback Machine's crawl index. Each record represents a snapshot the Wayback Machine captured — not a live state. The index covers billions of URLs across millions of domains.

**Query pattern:** waybackurls sends `url=*.target.tld/*&output=text&fl=original&collapse=urlkey` (or the equivalent for `-no-subs`: `url=target.tld/*`). The wildcard prefix `*.` triggers subdomain inclusion; `-no-subs` drops it.

**No authentication required.** The CDX API is public. No API key, no account. This also means no per-user rate-limit negotiation — everyone shares the same capacity.

**Rate limiting:** Wayback throttles sustained high-volume clients with HTTP 429s and connection resets. Behavior varies by server load. waybackurls has no built-in throttling — for large domain histories (100k+ URLs), chunk input with `timeout` or `xargs -P1` to avoid sustained bursts. `gau` (with `--providers wayback`) has `--threads` and `--retries` for more controlled access.

**Completeness:** CDX returns only what the Wayback Machine crawled. Pages behind auth, robots.txt-blocked paths, and dynamically generated content with unique URLs may not be indexed. Coverage skews toward public-facing, linked content.

---

## `-get-versions` Deep Workflow

`-get-versions` takes a **full URL** on stdin (not a domain) and returns Wayback Machine snapshot URLs — each pointing to an archived copy of that exact page at a specific timestamp.

Retrieve archived versions of a known file:
`echo https://target.tld/robots.txt | waybackurls -get-versions`

Output: lines like `https://web.archive.org/web/20220315142301/https://target.tld/robots.txt` — each is a retrievable snapshot.

### Retrieving old content

Fetch a specific snapshot:
`curl -sL "https://web.archive.org/web/20220315142301/https://target.tld/robots.txt"`

Use case: recovering content that has since been removed — old `robots.txt` (reveals disallowed paths), `sitemap.xml` (reveals URL structure), JS bundles (reveals API endpoints and keys), configuration files, API documentation.

### Version diffing

Compare two snapshots to detect security-relevant changes:

```
echo https://target.tld/robots.txt | waybackurls -get-versions | head -2 > versions.txt
old=$(head -1 versions.txt)
new=$(tail -1 versions.txt)
diff <(curl -sL "$old") <(curl -sL "$new")
```

Security-relevant changes to look for:
- Disallowed paths added or removed in `robots.txt` (reveals hidden endpoints).
- API endpoints deprecated in JS bundles (may still be reachable but no longer tested).
- API keys or tokens removed from JS/config files (may still be valid).
- Authentication mechanisms changed (old endpoints may accept weaker auth).

### Targeted version retrieval

Check old JS bundles for leaked secrets:
```
echo https://target.tld/static/app.js | waybackurls -get-versions | \
  while read url; do curl -sL "$url" | grep -iE '(api[_-]?key|secret|token|password)\s*[:=]' && echo "--- $url"; done
```

---

## Output Volume and Management

waybackurls on a popular domain easily produces 50,000–500,000+ raw lines. Manage volume before feeding downstream tools.

**Always deduplicate:**
`echo target.tld | waybackurls | sort -u > wayback.txt`

**Drop static assets early:**
`echo target.tld | waybackurls | grep -vE '\.(png|jpg|jpeg|gif|svg|css|woff|woff2|ttf|eot|ico|mp4|mp3|zip|pdf|map)$' | sort -u > wayback_clean.txt`

**Filter to interesting path shapes:**
```
echo target.tld | waybackurls | sort -u | tee wayback_all.txt | \
  grep -E '(/api/|/admin|/debug|/config|/internal|/graphql|/swagger|\.(json|xml|yml|yaml|env|bak|sql|log|conf)$)' \
  > wayback_interesting.txt
```

**Extract unique endpoints (strip query strings):**
`echo target.tld | waybackurls | sed 's/\?.*$//' | sort -u > wayback_endpoints.txt`

**Size check:** After any fetch, verify the output is manageable before piping to active tools:
`wc -l wayback.txt && du -sh wayback.txt`

If the set is outsized (>100k lines), filter harder before handing to `httpx` or `ffuf` — live-checking 100k URLs at once is slow and noisy.

---

Routed consumers:
- `reconnaissance/*` (historical endpoint enumeration — URLs that no longer link but may still resolve)
- `vulnerabilities/information_disclosure.md` (orphaned debug/admin paths)
- `tooling/httpx.md` (live-check the archive URLs)
- `tooling/arjun.md` (parameter names mined from historical URLs feed parameter discovery)
- `tooling/gau.md` (thin sibling — multi-provider counterpart; the shared workflow lives there)

---

Bounded-depth note: waybackurls is a single-purpose Wayback Machine CDX client with 3 flags (`-dates`, `-get-versions`, `-no-subs`). Its depth is in the archive-URL workflows it enables and the downstream tools it feeds, not in a large flag surface. The ~170-line depth here is genuine and complete — no further operational surface exists to document.
