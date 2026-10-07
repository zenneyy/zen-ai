---
name: second-order-injection
description: Second-order injection — stored user input triggering injection on a later request/path/user, across SQL/LDAP/XPath/template/expression/command/XSS classes; the attack is the storage path + the firing path together, not either in isolation
---

# Second-Order Injection

Second-order injection is the class where attacker-controlled input is stored safely at write time (parameterized query / escaped / sanitized) and then triggers an injection vulnerability on a later request path that reads the stored value and composes it into a sink without re-escaping. The primitive is **storage path (safe) + firing path (unsafe) = injection vulnerability only visible across both paths**: a user profile field stored via parameterized INSERT becomes a SQL injection sink when a reports page composes it into a dynamic query via string concatenation; a stored display name becomes LDAP injection when a sync job reads it. The question is never "is this input validated at storage time?" — it is "is this input re-escaped at every subsequent use point?"

This skill is cross-cutting. The underlying injection types (SQL, LDAP, XPath, template, expression, command, XSS) are owned by their respective skills; this skill owns the **two-path pattern** and the detection discipline for finding stored-then-fired primitives.

## Attack Surface

**Storage Paths (Attack Entry)**
- User registration / profile update (display name, bio, address fields)
- Comment / post / review submission
- Message / chat / notification content
- Workflow / pipeline / rule DSL fields (BPM task names, GitHub Actions step names)
- Admin-controlled config fields (feature flag names, email templates, SSO claim mappings)
- File uploads with metadata extracted and stored
- API-token / secret-management fields (token names, descriptions)
- Approved-but-attacker-authored content (approved comments, moderation queues)

**Firing Paths (Trigger Site)**
- Reports / analytics / search endpoints that compose dynamic queries from stored fields
- Scheduled jobs (cron, batch, ETL) that read stored data and feed it into another system
- Admin dashboards that render stored content with unescaped reach
- Email / notification composition reading stored display names
- Audit / log / monitoring that re-emits stored data
- Workflow execution that evaluates stored expressions / templates
- Cross-tenant sync / replication paths

**Classes of Downstream Injection Reached by Second-Order**
- **Second-order SQL injection** — stored field → unparameterized concat in a reports query. Primary owner: `sql_injection.md`.
- **Second-order XSS** — stored field → unescaped render in admin UI. Primary owner: `xss.md`.
- **Second-order LDAP** — stored field → unescaped filter construction. Primary owner: `ldap_injection.md`.
- **Second-order XPath** — stored field → unescaped XPath. Primary owner: `xpath_injection.md`.
- **Second-order template / expression** — stored template or expression → eval sink. Primary owner: `ssti.md` or `ssji.md`.
- **Second-order command injection** — stored shell-argument field → unquoted exec. Primary owner: `rce.md`.
- **Second-order SSRF** — stored URL → fetch without validation. Primary owner: `ssrf.md`.

**Input Vectors**
- Any user-authored content that persists.
- Any admin-authored config field.
- Any API-authored data (webhook payloads, OAuth claims, SAML attributes).
- File-metadata extraction (EXIF, PDF metadata, Office doc properties).

## Core Primitive — The Two-Path Pattern

**Primitive.** Input is stored safely (parameterized INSERT, escape-at-store, allowlist-at-store) but read later into a different code path that composes it without re-escaping.

**Pattern:**
```
Storage path:
  INSERT INTO users (name) VALUES (?); -- parameterized, safe

Firing path:
  SELECT * FROM audit WHERE user='" + stored_name + "'; -- concatenation, unsafe
```

The stored_name is "safe" when it entered the DB because INSERT was parameterized. The firing-path SELECT is unsafe because the developer trusted "input in DB is safe" — but the input was only escaped against INSERT-breaking, not against SELECT-breaking.

**Attack recipe:**
```
# Step 1 — Store the injection payload
POST /register HTTP/1.1
username=admin'--
# Server: INSERT INTO users (username) VALUES ('admin''--')  -- stored safely

# Step 2 — Trigger the firing path
GET /admin/user-reports?user=admin'-- HTTP/1.1
# Server reads username from DB and composes:
#   SELECT * FROM users_report WHERE username = 'admin'--'
# The -- comments out the trailing quote; injection fires.
```

**Scope.** The attack is undetectable in input-validation-at-storage scans; the firing path is often an admin-only or batch-job code path with different reviewers.

## Measurement Discipline — Time-Correlation Attribution

Second-order attacks have a time-separation between storage and firing. Pentester discipline:

1. **Timestamp the storage request.** Attacker submits the injection payload at T=0.
2. **Observe immediate response.** Should be normal (safe at storage time).
3. **Trigger the firing path.** Depending on the application: admin visit, scheduled job execution, cron run, user activity (search, report generation).
4. **Observe firing-path behavior.** The injection fires at T=firing-event.
5. **Correlate.** The attack is attributable to the storage event, not the firing-event trigger.

**Natural trigger latency ranges:**
- Admin visit → minutes to hours (admin's own work pattern).
- Scheduled job → fixed interval (daily, hourly, every 5 min).
- User action (search, report) → attacker-triggerable (bring your own user).
- Replication / sync → batched, typically every N minutes.

## Detection Channels

### Storage-Side Reflection

Store a canary payload with a known marker. Observe later reads of the stored data for the marker's post-escape form.

### Firing-Site Impact

The firing-path injection produces its downstream effect — SQL error, authentication bypass, XSS execution, LDAP filter error.

### Time-Correlated Logging

Server-side logs show the firing-path error with a trace back to the stored-value origin.

### OAST via Firing Path

Store a payload that triggers an OAST callback on firing — DNS/HTTP hit arrives at the firing-event time, not the storage time.

## Testing Methodology

1. **Enumerate storage paths.** Every user field that persists.
2. **Enumerate firing paths.** Every admin-visible / batch-job / cross-user path that reads stored data.
3. **Submit a universal injection probe at each storage path.** `'-- --" or 1=1; drop table X; { "$where": "..." }; __proto__; CRLF; template-{{...}};`.
4. **Trigger the firing path.** Visit admin UI, trigger search, wait for scheduled job.
5. **Observe firing-path behavior.** Error? Side effect? OAST callback?
6. **Confirm storage.** Verify the stored value is unchanged (not auto-escaped to a non-injectable form).

## Validation

- **Firing-path effect must correlate with the storage event.** A random admin-page error unrelated to the probe is coincidence; a page error IMMEDIATELY after admin loaded the user list containing the probe is confirmation.
- **The injection must fire from the stored content, not from a request parameter.** Verify by removing the request-parameter paths; the stored content alone should fire.
- **The firing path must be reachable by attacker-triggerable means.** A code path only reachable by one specific admin manually is weaker than one triggerable by any user's search.

## False Positives

- A storage-path value that is actually re-escaped at the firing path.
- A firing-path error that is caused by a different field.
- A canary that fires at storage time (first-order injection; route to the first-order skill).

## Impact and Chaining

**Direct impact.** The injection class reached by the firing path:
- Second-order SQL → data exfil / RCE depending on DBMS.
- Second-order XSS → admin impersonation if the firing path is admin-rendered.
- Second-order LDAP → directory enumeration / auth bypass.
- Second-order XPath / template / expression → the corresponding class impact.
- Second-order command → RCE.
- Second-order SSRF → internal network reach.

**Scope expansion.** Second-order attacks escalate privilege: the attacker's input is written as a low-privileged user, but the firing path often runs with elevated privilege (admin dashboard, system batch job, cross-tenant replication). The attack is **privilege-elevation-by-stored-content**.

**Upstream enablers.** Any storage path with user-controlled data.

**Downstream.** The specific injection class' downstream — route to the primary-owner skill for post-exploitation.

## Pro Tips

- **The storage path doesn't need to be an injection sink.** Parameterized INSERT is safe. The attack is in the firing path.
- **Admin dashboards are prime firing-path targets.** Developers often assume "the admin trusts the data they're viewing," which is wrong.
- **Scheduled jobs are stealth firing paths.** The injection fires without any attacker-triggered request; the attribution requires looking at job execution logs.
- **Cross-tenant replication is a cross-tenant privilege-elevation path.** Attacker-controlled data in Tenant A reaches Tenant B's replication consumer, which may run with cross-tenant admin.
- **Database-row-triggers (ON INSERT / ON UPDATE) are second-order sinks.** Triggers that compose dynamic SQL from NEW.column_name are a classic case.
- **ETL / data-pipeline systems are high-value targets.** Fleet CVE-2026-34385 (Apple MDM profile delivery) is this class.

## Tooling

- **Burp Suite Scanner** — second-order probe mode (track stored payloads).
- **sqlmap --second-order** — second-order SQL injection automation.
- **Manual stored-payload tracker.** Spreadsheet of (payload, storage endpoint, time) → observe firing side.

## Summary

Second-order injection is the two-path pattern: storage (safe) + firing (unsafe). The attack reaches SQL, LDAP, XPath, template, expression, command, or XSS classes on the firing path, each primary-owned by its respective skill. Second-order attribution requires time-correlation between storage and firing events. The 2024-2026 frontier covers 35+ CVEs including EverShop (CVE-2026-25993 CVSS 9.8), n8n expression injection (CVE-2026-27493 CVSS 9.0), Hibernate (CVE-2026-0603 CVSS 8.3), SuiteCRM (CVE-2026-29096), Fleet Apple MDM profile delivery (CVE-2026-34385), ZoneMinder (CVE-2026-27470), mailcow (CVE-2026-40871), and the WordPress plugin cluster (Ultimate Member, Mail Mint, Quiz Master Next, Tutor LMS, Page and Post Clone). This class is bounded in primitive-shape (one pattern, many downstream classes) — the trio stays compact; the primitive is complete at this depth. The two deep siblings carry additional depth: `second_order_injection_advanced_deep.md` owns per-class second-order recipes and time-correlation methodology; `second_order_injection_novel_deep.md` owns the 2024-2026 CVE catalogue.
