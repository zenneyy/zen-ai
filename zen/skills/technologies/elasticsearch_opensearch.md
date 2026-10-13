---
name: elasticsearch_opensearch
description: Elasticsearch and OpenSearch security testing covering unauthenticated cluster access, query injection, Painless scripting sandbox boundaries, snapshot/restore abuse, and the MVEL→Groovy→Painless scripting CVE lineage
---

# Elasticsearch & OpenSearch

Elasticsearch and OpenSearch are search and analytics engines whose REST API exposes cluster management, data query, and server-side scripting on a single HTTP port — with security historically disabled by default. This skill owns Elasticsearch/OpenSearch-specific surfaces: unauthenticated cluster access, `_search`/`_sql` query injection, Painless scripting RCE boundaries, stored-script abuse, snapshot/restore to attacker-controlled repositories, `_cat`/`_cluster`/`_nodes` information disclosure, and Kibana/OpenSearch Dashboards as a pivot. SSRF reach to an internal Elasticsearch routes through `ssrf`; query injection that crosses into the NoSQL injection pattern class references `nosql_injection`; scripting-based command execution references `rce` for the general RCE classification. Data exposure patterns reference `information_disclosure`.

## Attack Surface

- **Default ports:** 9200 (HTTP REST API), 9300 (transport/inter-node), 5601 (Kibana), 9600 (OpenSearch Performance Analyzer)
- **REST API surface:** `_search`, `_sql`, `_msearch`, `_mget`, `_bulk`, `_analyze`, `_scripts`, `_snapshot`, `_reindex`, `_cat/*`, `_cluster/*`, `_nodes/*`, `_tasks`, `_ingest/pipeline`
- **Scripting engines:** Painless (ES 5.0+ / all OpenSearch), historically MVEL (ES <1.2) and Groovy (ES 1.2–4.x)
- **Plugins/extensions:** Kibana (dashboards + Dev Tools console), OpenSearch Dashboards, Security plugin (Open Distro / OpenSearch Security), Alerting, SQL, ML nodes
- **Data exposure:** indexed documents (logs, metrics, application data, PII), cluster topology, JVM arguments, filesystem paths

## Reconnaissance

**Fingerprinting** (unauthenticated)
```
# Cluster info — version, build, Lucene version (port 9200)
curl -s http://<target>:9200/
# Response: {"name":"node-1","cluster_name":"...","version":{"number":"8.17.0",...},"tagline":"You Know, for Search"}

# OpenSearch variant
curl -s http://<target>:9200/
# Response: {"name":"...","cluster_name":"...","version":{"distribution":"opensearch","number":"2.18.0",...},"tagline":"The OpenSearch Project: ..."}

# Cluster health + node count
curl -s http://<target>:9200/_cat/health?v
curl -s http://<target>:9200/_cat/nodes?v

# Index inventory
curl -s http://<target>:9200/_cat/indices?v

# Kibana / OpenSearch Dashboards
curl -sI http://<target>:5601/
```

**Security posture detection** — the first gate on every engagement:

Measured on Elasticsearch 8.17.0: security is **enabled by default** (`xpack.security`). Unauthenticated `GET /` returns HTTP 401 with `WWW-Authenticate: Basic, Bearer, ApiKey`. HTTPS is auto-configured with a self-signed certificate. This is a measured negative — on ES 8.x, unauthenticated access requires the operator to have **explicitly disabled** security (`xpack.security.enabled: false`).

Measured on OpenSearch 2.18.0: the Security plugin is enabled by default. Since OpenSearch 2.12.0, `OPENSEARCH_INITIAL_ADMIN_PASSWORD` is **required** at startup — the container will not start without it. Pre-2.12 default was `admin:admin`. Demo users ship by default: `admin`, `logstash`, `kibanaserver`, `snapshotrestore`.

ES 7.x and earlier shipped security OFF by default — all APIs unauthenticated over plaintext HTTP.

```
# Quick auth check
curl -s -o /dev/null -w "%{http_code}" http://<target>:9200/
# 200 = no auth (security disabled); 401 = auth required

# OpenSearch demo-user check
curl -sk -u admin:admin https://<target>:9200/   # pre-2.12 default
```

## Key Vulnerabilities

### Unauthenticated Cluster Access

When security is disabled (ES 7.x default, ES 8.x with `xpack.security.enabled: false`, OpenSearch with `DISABLE_SECURITY_PLUGIN=true`), the full REST API is unauthenticated. Measured on ES 8.17.0 with security disabled: `GET /`, `_cat/nodes`, `_cat/indices`, `_cluster/health`, `_nodes`, `_search`, document indexing — all return HTTP 200 with full data, no credentials required. `_nodes` exposes JVM arguments, filesystem paths, plugin lists, and OS details.

### Query Injection (_search / _sql)

Applications that interpolate user input into Elasticsearch query DSL or `_sql` queries without parameterization are vulnerable to query injection. The attacker modifies the query structure to access unauthorized indices, extract fields not intended by the application, or trigger server-side scripts.

```
# DSL injection — closing the intended match and injecting a bool query
{"query":{"bool":{"must":[{"match":{"title":"USER_INPUT"}},{"match_all":{}}]}}}
# If USER_INPUT is: "}},{"match_all":{}}]},"_source":["password"],
#   the attacker reads the password field from documents they shouldn't access.

# _sql injection
POST /_sql {"query":"SELECT * FROM index WHERE field='USER_INPUT'"}
# Standard SQL injection applies (UNION, subquery, etc.)
```

Route pure-NoSQL injection patterns (operator injection, `$where`) to `nosql_injection`; Elasticsearch query injection is structurally closer to JSON-DSL manipulation than to MongoDB-style operator injection.

### Scripting Engine Lineage — MVEL → Groovy → Painless

Elasticsearch's scripting surface has carried three sandbox-escape CVE generations:

**CVE-2014-3120** (CVSS 8.1) — ES <1.2 enabled MVEL dynamic scripting by default. Arbitrary Java code execution via `_search` `script_fields`. No sandbox.

**CVE-2015-1427** (CVSS 9.8) — ES 1.2–1.4.2 replaced MVEL with Groovy inside a sandbox, but the sandbox was bypassable via Java reflection. Exploit: `.class.forName('java.lang.Runtime').getMethod('exec',''.class).invoke(...)` in a Groovy script field. The definitive scripting sandbox escape — it drove Elastic to replace Groovy entirely.

**Painless (ES 5.0+ / all OpenSearch)** — purpose-built scripting language with a **class allowlist** (not a blocklist). Measured on ES 8.17.0: `Runtime.getRuntime().exec("id")` → `cannot resolve symbol [Runtime]`; `new ProcessBuilder(["id"]).start()` → `Not a type [ProcessBuilder]`; `new java.io.File("/etc/passwd").text` → `Not a type [java.io.File]`; `Thread`, reflection — all blocked. No public Painless sandbox escape CVE exists as of this writing. The sandbox has held since ES 5.0 (2016).

**Residual Painless risk:** even without a sandbox escape, Painless scripts execute server-side compute. An attacker who can create stored scripts (`POST /_scripts/<id>`) controls query-time logic — useful for data exfiltration via computed fields, DoS via expensive scripts, or planting backdoor logic in stored script pipelines.

### Log4Shell Dependency Impact (CVE-2021-44228)

Elasticsearch 7.x bundled Log4j 2.x. ES versions before 7.16.1 and 6.8.21 were affected by Log4Shell JNDI injection. This is not an ES-native vulnerability — it is a dependency impact. Exploitation requires the attacker to control a value that reaches a Log4j log call (e.g. a header, a query string, or indexed document content that triggers a log message). ES 8.x ships with Log4j vulnerability mitigations.

### CVE-2021-22145 — Memory Disclosure (CVSS 6.5)

ES 7.10.0–7.13.3: malformed query triggers error reporting that leaks memory contents from the ES process. Information disclosure — may contain indexed data, credentials, or internal state.

### Snapshot/Restore Abuse

The `_snapshot` API creates and restores index snapshots to configured repositories (filesystem, S3, GCS, Azure, HDFS). If the attacker controls a repository configuration:
- **Exfiltration:** snapshot indices to an attacker-controlled S3 bucket or NFS share.
- **Injection:** restore a snapshot containing attacker-crafted documents or scripts into the cluster.

Measured: `PUT /_snapshot/test_repo` fails with `location doesn't match any of the locations specified by path.repo` — the `path.repo` setting must be configured; snapshot abuse is not exploitable by default. But the API is reachable without auth when security is off.

### Kibana / OpenSearch Dashboards as Pivot

Kibana (`:5601`) provides a Dev Tools console that proxies arbitrary REST API calls to Elasticsearch. If Kibana is reachable (especially with default/no credentials), it grants the same access as direct API access but through a web UI that may bypass network-level restrictions on port 9200. OpenSearch Dashboards provides equivalent functionality.

## Testing Methodology

1. **Fingerprint** — `GET /` on port 9200; determine ES vs OpenSearch, exact version, security posture (200 vs 401).
2. **Auth matrix** — unauthenticated, default creds (`admin:admin` for OpenSearch pre-2.12, `elastic:changeme` for older ES), API keys in application configs.
3. **Data inventory** — `_cat/indices?v` → list all indices; `_search` on high-value indices (logs, users, sessions, credentials); `_nodes` for cluster topology and JVM details.
4. **Scripting version check** — if ES <5.0, test Groovy sandbox escape (CVE-2015-1427). If ES 5.0+, note Painless sandbox; test stored-script creation (`POST /_scripts/test`).
5. **Snapshot API** — `GET /_snapshot` for configured repos; test repo creation if admin-level access.
6. **Kibana/Dashboards** — probe `:5601`, test Dev Tools console access.
7. **Query injection** — if the application exposes search functionality backed by ES, test query DSL injection and `_sql` injection.

## Validation

1. Show `GET /` response with version, cluster name, and the tagline confirming the product.
2. Unauthenticated access: show a `_search` response returning indexed documents (with sensitive data highlighted) or `_cat/indices` listing all indices.
3. Scripting: show the Painless sandbox blocking the escape attempt (the measured negative), or on older versions, the successful sandbox escape with command output.
4. Data theft: show the recovered sensitive data (credentials, PII, tokens) with the index and document IDs.
5. Snapshot abuse: show the snapshot configuration and the exfiltration path.

## False Positives

- **ES 8.x / OpenSearch 2.x with default security** — unauthenticated access returns 401; the cluster is not exposed. The finding requires security to be explicitly disabled.
- **Managed services** (AWS OpenSearch Service, Elastic Cloud) — security is enforced by the provider; CONFIG/snapshot/scripting surfaces are restricted. Down-rate to the data-access finding if credentials are compromised.
- **Painless scripting available** — Painless is intentionally exposed for query-time computation; its availability is not a finding. The finding is a stored-script write by an unauthorized user, or a sandbox escape (currently no public CVE).
- **`_cat` endpoints returning only health/status** — cluster health is low-sensitivity; the finding is when `_cat/indices`, `_nodes`, or `_search` return document-level data or internal topology.
- **CVE-2015-1427 on ES 5.0+** — Groovy was replaced by Painless; the CVE does not apply. Confirm the version before reporting scripting vulnerabilities.

## Impact

- Full index read/write: exfiltrate all indexed data (logs, PII, credentials, application records), modify or delete documents.
- Cluster topology and JVM disclosure (`_nodes`) → internal network mapping, version-targeted attacks.
- Server-side scripting (Groovy sandbox escape on <5.0) → OS-level RCE.
- Stored-script injection → persistent query-time backdoor logic.
- Snapshot exfiltration → bulk data theft to attacker-controlled storage.
- Kibana/Dashboards pivot → web-UI-based access to the full REST API, bypassing network restrictions on 9200.

## Pro Tips

1. The version determines the entire attack tree: <1.2 → MVEL RCE; 1.2–4.x → Groovy sandbox escape (CVE-2015-1427); 5.0+ → Painless (no public escape). Always fingerprint first.
2. ES 8.x security ON by default is a measured negative — an unsecured ES 8.x cluster is a deliberate misconfiguration, not a default.
3. `_cat/indices` is the fastest data-value triage: index names like `users`, `sessions`, `logs-*`, `audit-*` signal what's worth querying.
4. `_nodes?pretty` leaks JVM flags, filesystem paths, plugin lists, and sometimes environment variables — check it even when the data indices are empty.
5. OpenSearch pre-2.12 shipped `admin:admin` — always test this on OpenSearch deployments.
6. Pair with `ssrf` for SSRF-to-ES reach, `nosql_injection` for injection pattern cross-reference, `rce` for scripting RCE classification, `information_disclosure` for data exposure, and `grafana_prometheus` (Elasticsearch is a common Grafana data source).

## Summary

Elasticsearch and OpenSearch expose their full attack surface — data query, cluster management, server-side scripting, and snapshot control — on a single REST API port. ES 8.x and OpenSearch 2.12+ ship security on by default, but legacy and misconfigured deployments remain widespread. The scripting CVE lineage (MVEL → Groovy → Painless) drove three generations of sandbox escapes; Painless has held since ES 5.0, but stored-script creation remains a risk when the API is writable. An exposed cluster is a data exfiltration, topology disclosure, and potential RCE finding — determine the version, test the scripting surface, inventory the indices, and chain to deeper compromise.
