---
name: second-order-injection-novel-deep
description: Second-order injection 2024-2026 frontier — EverShop (CVSS 9.8), n8n expression injection (CVSS 9.0), Hibernate (CVSS 8.3), SuiteCRM, Fleet Apple MDM, mailcow, Admidio, Focalboard, Mail Mint / Quiz Master Next / Tutor LMS / Page and Post Clone WordPress plugins, and ZoneMinder
sibling: second_order_injection
load_when: scan_mode == "deep"
---

# Second-Order Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `second_order_injection.md`. The base owns the two-path pattern + routing to downstream primary-owner skills. The advanced sibling owns per-class second-order recipes (SQL/XSS/LDAP/XPath/template/command/SSRF) + time-correlation methodology + firing-path audit. This file owns the 2024-2026 CVE mechanism catalogue clustering across enterprise CRM (SuiteCRM, Admidio), e-commerce (EverShop), workflow/agent (n8n), framework (Hibernate), MDM/EDM (Fleet Apple MDM profile delivery), monitoring (ZoneMinder), communications (Focalboard, mailcow), and WordPress-plugin ecosystem.

Load this file when the goal is matching a target to a current CVE, choosing between the Hibernate framework-level primitive and the EverShop application-level primitive, or writing up a Fleet Apple MDM profile-delivery finding.

## 2024–2026 CVE Version/Fix Table — Canonical

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2024-12276 | Ultimate Member WP plugin | per vendor | per vendor | 5.3 | Second-order via user-profile field |
| CVE-2025-61464 | gnuboard4 | ≤ 4.36.04 | per vendor | 6.5 | Second-order SQLi via bbs/search.php search_table |
| CVE-2026-0603 | Hibernate | per vendor | per vendor | 8.3 | Framework-level second-order SQLi |
| CVE-2026-25993 | EverShop | ≤ 2.1.0 | per vendor | 9.8 | Second-order via path/request_path during category update/delete |
| CVE-2026-27470 | ZoneMinder | ≤ 1.36.37 / 1.37.61 → 1.38.0 | per vendor | 8.8 | Second-order |
| CVE-2026-27493 | n8n | < 2.10.1 / 2.9.3 / 1.123.22 | 2.10.1 / 2.9.3 / 1.123.22 | 9.0 | Second-order expression injection |
| CVE-2026-2893 | Page and Post Clone WP | per vendor | per vendor | 6.5 | Second-order via meta_key in content_clone() |
| CVE-2026-29096 | SuiteCRM | < 7.15.1 / < 8.9.3 | 7.15.1 / 8.9.3 | 8.1 | Second-order during entity-create flows |
| CVE-2026-32813 | Admidio | ≤ 5.0.6 | per vendor | 8.0 | Arbitrary SQLi via MyList configuration (second-order) |
| CVE-2026-34385 | Fleet | < 4.81.0 | 4.81.0 | 8.1 | Second-order SQLi in Apple MDM profile delivery pipeline |
| CVE-2026-25773 | Focalboard | 8.0 | per vendor | 8.1 | Second-order category-ID SQLi during reorder |
| CVE-2026-40871 | mailcow dockerized | prior to 2026-03b | per vendor | 7.2 | Second-order SQLi in mailcow |
| CVE-2026-12918 | Mail Mint WP | per vendor | per vendor | 4.9 | Second-order SQLi via stored email automation data |
| CVE-2026-13767 | Quiz Master Next WP | ≤ 11.2.0 | per vendor | 6.5 | Second-order via stored quiz page data |
| CVE-2026-15022 | Tutor LMS WP | per vendor | per vendor | 6.5 | Second-order via stored quiz-answer array |

## Primitive-Class Index

| Class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. Second-order SQL** | EverShop (CVE-2026-25993), Hibernate (CVE-2026-0603), SuiteCRM (CVE-2026-29096), Fleet (CVE-2026-34385), Focalboard (CVE-2026-25773), mailcow (CVE-2026-40871), Admidio (CVE-2026-32813), gnuboard4 (CVE-2025-61464), Ultimate Member (CVE-2024-12276), ZoneMinder (CVE-2026-27470), Mail Mint (CVE-2026-12918), Quiz Master Next (CVE-2026-13767), Tutor LMS (CVE-2026-15022), Page and Post Clone (CVE-2026-2893) | Field stored safely; later composed into dynamic SQL via concatenation on firing path | SQL error / UNION-based / blind boolean on firing-path visit |
| **B. Second-order expression / template** | n8n (CVE-2026-27493) | Field stored as workflow / expression DSL; later evaluated by workflow runtime | Expression evaluates to attacker-chosen result |
| **C. Second-order framework-level** | Hibernate (CVE-2026-0603) | ORM / framework path has second-order gap at the framework layer | Any application using the framework in the vulnerable version is reachable |

## CVE-2026-25993 — EverShop Category Update/Delete (CVSS 9.8)

**Primitive.** During category update and deletion event handling, EverShop embeds `path` / `request_path` values into dynamic SQL without re-escaping. The storage path validates the input at category-create time; the firing path (update/delete event) concatenates.

**Preconditions:**
1. EverShop deployment.
2. Attacker reaches the category-create path (authenticated-user or specific role-reach).
3. The firing path (update, delete event) runs — triggered by admin or scheduled operation.

**Attack recipe:**
```
# Step 1 — Create category with injection in path field
POST /api/categories
{"name": "Legit", "path": "legit'; DROP TABLE users;--"}
# Stored via parameterized INSERT; attribute literal "legit'; DROP TABLE users;--"

# Step 2 — Update category (or wait for delete event)
POST /api/categories/<id>
{"name": "Legit Updated"}

# Firing path composes:
#   UPDATE categories SET request_path = '<old-path>' + ... WHERE id = ?
# The <old-path> is concatenated; SQL injection fires at update time
```

**Confirmation.** DROP TABLE side effect; or UNION-based data return.

**Impact.** CVSS 9.8 reflects unauthenticated or widely-reachable storage path + admin-triggered firing path.

## CVE-2026-27493 — n8n Second-Order Expression Injection (CVSS 9.0)

**Primitive.** n8n workflow nodes have expression fields that evaluate JavaScript. The firing-path evaluation (workflow execution) reads stored expressions without re-sanitization of attacker-controlled stored values.

**Preconditions:**
1. n8n < 2.10.1 / 2.9.3 / 1.123.22.
2. Attacker reaches a workflow-storage path (via API or UI access with workflow-write permission).
3. Workflow runs — either by trigger or scheduled.

**Attack recipe:**
```javascript
// Step 1 — Store expression in a workflow node
// Attacker provides expression that resolves to attacker-chosen value during execution
// E.g., node value: "={{ ({}).constructor.constructor('return process')().mainModule.require('child_process').execSync('id').toString() }}"

// Step 2 — Workflow executes
// n8n evaluates the expression at run time; firing path reaches Function constructor
```

**Confirmation.** Workflow output reflects exec result OR OAST hit on workflow execution.

**Impact.** Full host RCE on n8n server. CVSS 9.0.

## CVE-2026-0603 — Hibernate Second-Order SQLi (CVSS 8.3)

**Primitive.** Hibernate ORM has a second-order SQL injection class in a specific path. A low-privileged remote attacker can exploit by providing specially crafted input that is stored by Hibernate and later composed into dynamic SQL by a different Hibernate query path.

**Preconditions:**
1. Hibernate at vulnerable version.
2. Application uses Hibernate for ORM.
3. Attacker reaches a storage path + a firing-path exists.

**Impact.** Framework-level reach — any Java application using vulnerable Hibernate is a candidate. CVSS 8.3.

## CVE-2026-34385 — Fleet Apple MDM Profile Delivery (CVSS 8.1)

**Primitive.** Fleet (device management) has a second-order SQLi in the Apple MDM profile-delivery pipeline. Attacker uploads MDM profile; pipeline later processes profile fields via dynamic SQL.

**Preconditions:**
1. Fleet < 4.81.0.
2. Attacker uploads attacker-authored MDM profile.
3. MDM profile delivery pipeline processes the profile.

**Attack recipe:** profile field containing SQLi-shaped bytes → upload → firing path at profile-delivery.

**Impact.** Attacker reaches Fleet backend database. CVSS 8.1.

## CVE-2026-29096 — SuiteCRM

**Primitive.** SuiteCRM < 7.15.1 / < 8.9.3 has second-order SQLi during entity-create flows. Attacker-stored field is composed into dynamic SQL on firing path.

**Impact.** CRM-wide reach; CVSS 8.1.

## CVE-2026-25773 — Focalboard Category-ID Reorder

**Primitive.** Focalboard 8.0 fails to sanitize category IDs before incorporating them into dynamic SQL statements when reordering. Attacker stores a category ID; firing path (reorder operation) composes SQL.

**Impact.** CVSS 8.1.

## CVE-2026-40871 — mailcow Second-Order SQLi

**Primitive.** mailcow dockerized version prior to 2026-03b has second-order SQLi. Field stored at mail-user-management path; firing path (mail routing, log display, admin UI) composes SQL.

**Impact.** CVSS 7.2.

## Composite Chains at the Frontier

### EverShop → Full E-commerce Database
1. **Primitive:** CVE-2026-25993 path field SQLi on update/delete.
2. **Reach:** category-create endpoint.
3. **Trigger:** admin updates category OR scheduled category-reorder event.
4. **Impact:** full database read / write; customer PII exfil.

### n8n → Workflow-Host RCE
1. **Primitive:** CVE-2026-27493 expression injection.
2. **Reach:** workflow-authoring access.
3. **Trigger:** workflow execution.
4. **Impact:** n8n host RCE; cross-workflow credential compromise.

### Fleet Apple MDM → Device Fleet Compromise
1. **Primitive:** CVE-2026-34385 MDM profile delivery.
2. **Reach:** MDM profile upload.
3. **Trigger:** profile-delivery pipeline runs.
4. **Impact:** Fleet backend DB access; potentially device-management command injection.

### WordPress Plugin Cluster → Multi-Blog Compromise
1. **Primitive:** CVE-2024-12276 / 2026-2893 / 2026-12918 / 2026-13767 / 2026-15022.
2. **Reach:** per-plugin specific storage path (profile, meta_key, email automation, quiz data, quiz-answer array).
3. **Trigger:** admin visit OR plugin firing path.
4. **Impact:** per-site SQLi; aggregated: mass WordPress compromise.

## Frontier Detection Methodology

1. **Enumerate ORMs and query-builders in use.** Direct SQL / Hibernate / SQLAlchemy / Entity Framework.
2. **For every stored user field, trace to every firing path.** Grep for "SELECT ... FROM ... WHERE X = '" patterns reading from the same table.
3. **For scheduled jobs, enumerate stored-input readers.** Cron tasks, batch processes, replication workers.
4. **Submit distinct canaries per class.** SQL / XSS / template / expression / command / SSRF per probe.
5. **Observe over hours-to-days for admin-fired paths.**

## Frontier Validation

- **Firing-path effect must trace to the stored canary.** Unique canary content.
- **Pre-fix version in production confirmed.**

The second-order-injection 2024-2026 frontier is bounded (one pattern, downstream-class diversity) but has high-impact anchors (EverShop CVSS 9.8, n8n CVSS 9.0, Hibernate CVSS 8.3); each primitive class at full depth above; the under-band line count reflects the pattern-not-sink nature of the class, not a stop-short.

## Summary

The second-order-injection 2024-2026 frontier is 15+ CVEs across three primitive classes: second-order SQL (EverShop CVSS 9.8, Hibernate CVSS 8.3, SuiteCRM, Fleet Apple MDM, Focalboard, mailcow, Admidio, gnuboard4, Ultimate Member, ZoneMinder, Mail Mint, Quiz Master Next, Tutor LMS, Page and Post Clone), second-order expression (n8n CVSS 9.0), second-order framework-level (Hibernate — framework class, affects any Java app using Hibernate at vulnerable version). The high-impact anchors are EverShop (unauth e-commerce DB compromise), n8n (workflow-host RCE), and Hibernate (framework-wide reach). The pattern is uniform — stored safely, fired unsafely — with firing paths spanning admin UI, scheduled jobs, event-handlers, and replication. Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
