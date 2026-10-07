---
name: logging-alerting-failures
description: Logging and alerting failures (OWASP A09:2025) — insufficient logging of auditable events, missing alerting, log injection / CRLF-based log forgery (CWE-117), sensitive-data leakage into logs (CWE-532), and audit-trail tampering; a bounded primitive set where the "vulnerability" is often the absence of a signal
---

# Logging and Alerting Failures

Logging and alerting failures are the OWASP A09:2025 class where attacker activity is not recorded, not surfaced, or recorded in a form the defender cannot trust. The primitive is **absence-or-corruption-of-signal in the detection pipeline**: a privilege-boundary-crossing event (admin login, authorization denial, mass-data export, configuration change, security exception) is not written to any log at all; the log exists but no alert fires; the log exists and alerts fire but the entries have been forged via CRLF injection to hide the attacker's real activity; secrets land in logs that are retained beyond their rotation window; audit-trail tables permit DELETE from the application role. The question is never "is logging configured?" — it is "would the SIEM operator notice this specific attack within the attacker's expected dwell time, and would the log evidence hold up at post-incident forensic review?"

**Bounded-primitive-set note.** Logging and alerting failures are a genuinely bounded class with five primitives: insufficient logging, missing alerting, log injection / CRLF forgery, secrets-in-logs, and audit-trail tampering. The log-injection *mechanism* overlaps the general injection classes — this skill owns the *log-channel expression* and the detection-gap framing; the mechanism-level depth of CRLF / format-string / NoSQL injection into log fields routes to the respective injection skills. The class resists CVE-catalog treatment because the vulnerability is often the *absence* of a signal; OWASP A09 itself notes it is "difficult to test, underrepresented in CVE and CVSS data." The compact depth here reflects the real surface, not under-coverage.

## Attack Surface

**Authentication / Session Events (expected to be logged)**
- Login attempts (success + failure, with reason code)
- Authorization denials (403, 401 on authenticated endpoints)
- Password reset / email change / 2FA setting changes
- Session hijack indicators (impossible travel, IP change mid-session, concurrent sessions)
- Admin impersonation ("sudo"-shaped operations)

**Privilege-Boundary-Crossing Events**
- Admin actions (role grants, user creation, resource ACL changes)
- Data export / bulk download operations
- Configuration changes (feature flags, security settings, external integration config)
- Secrets access (reading a stored credential, decrypting a vault entry)
- Infrastructure actions (cloud API calls, resource provisioning)

**Security-Exception Events**
- WAF rule triggers
- CSP violations reported to the configured endpoint
- Rate-limit violations
- Serialization errors (deserialization exceptions on untrusted input)
- SQL / NoSQL / template errors on request paths that should not produce them

**Log Pipeline Components**
- Application logger (SLF4J + Log4j2, Serilog, structlog, logrus, winston)
- Log transport (syslog over UDP, syslog over TLS RFC 5425, Fluentd / Fluent Bit, Vector, OTel collectors)
- Log aggregation (Elasticsearch / Loki / Splunk / Datadog / Elastic / CloudWatch Logs / Google Cloud Logging)
- Alerting layer (Alertmanager, PagerDuty, Opsgenie, Datadog monitors, Elastic alerting)
- Audit database (application-local audit tables, chain-of-custody blobs, S3 object-lock audit storage)

**Input Vectors — for the injection sub-primitive**
- Any user-supplied field logged without CRLF neutralization (username, user-agent, URL path, query string, request body field)
- Error paths that log the full HTTP request repr (common Flask / Rails / Spring default handlers)
- Debug-level loggers enabled in production
- Stack traces that include request state (e.g., Flask DEBUG=True)

## Core Primitive — Insufficient Logging (OWASP A09)

**Primitive.** An auditable event occurs but no log entry is written. Attacker activity leaves no trace at the SIEM; the defender cannot see the attack happened at all. CWE-778.

**All-of preconditions:**
1. The event is privilege-boundary-crossing or security-relevant (per the Attack Surface list above).
2. The application does not call its logger on the event's code path.
3. The event does not reach a downstream signal (e.g., a WAF or reverse proxy that would log).

**Attack-detection discipline (external test — the strongest signal).**
```
Fire the expected-to-be-logged event; check whether a corresponding log entry appears
in the SIEM within the SLA for log propagation (typically 5-30 seconds).

Example probes:
  - Submit 10 failed logins for a user → expect 10 "login_failed" entries.
  - Issue a 403-expected admin endpoint call from a non-admin → expect "authz_denied" entry.
  - Trigger a known CSP violation on a page → expect a `/csp-report` endpoint hit AND
    an aggregated log entry.
```

**Confirmation signals.**
1. **No log entry.** The expected event occurred (verified by server behavior or secondary signal) but no entry appears in the SIEM search for that event's identifiable field (user ID, URL path, timestamp window).
2. **Partial log entry.** The event appears in access logs (because a reverse proxy writes them) but not in the application's own structured security log, so richer event context (user ID, authz decision, matched rule) is missing.
3. **Log entry present but drops before SIEM.** The application writes to a file / stdout and the shipping pipeline (Fluent Bit filter, log-format-mismatch parser) drops the event. The log file has it; the SIEM does not.

**False positives.** A test environment with reduced logging may not reproduce the production surface. Verify in a staging environment that mirrors production's logging configuration; a staging-only "no logging" finding may not mean production is affected.

**Primary ownership.** Mechanism owned here; the specific audit-list of what *should* be logged lives in OWASP A09:2025 and ASVS 5.0 V8/V9 (routes to those as the catalog authority).

## Core Primitive — Missing Alerting

**Primitive.** The log entry is written and shipped to the SIEM — but no alert fires on it, or the alert fires with a signal-to-noise ratio so low that operators ignore it. Attack visibility exists in post-incident forensics but is unavailable at the time of attack.

**All-of preconditions:**
1. The event is logged.
2. No alerting rule matches the event; OR the matching rule has a threshold the attacker's volume stays below; OR the rule fires but is routed to a dashboard no operator watches; OR the rule has such a high false-positive rate that the specific true-positive gets ignored.

**Attack-detection discipline.**
```
Fire a sequence of events that should trigger a specific alert (10 failed logins
in 60 seconds, 1 impossible-travel event, 1 admin-privilege grant). Observe
whether the on-call operator receives a page / Slack message / dashboard
highlight within the alerting SLA.
```

**Confirmation signals.**
1. **No alert received.** Alerting rule missing OR threshold-above-attacker-volume.
2. **Alert routed to a disabled channel.** Email list that nobody reads, Slack channel that is muted, dashboard that nobody watches.
3. **Alert received but with so many false-positive peers it is deprioritized.** "Alert fatigue."

## Core Primitive — Log Injection / CRLF Forgery (CWE-117)

**Primitive.** A user-controlled string is logged without CRLF neutralization. The attacker inserts `\r\n` (or raw `\n`) followed by a plausibly-shaped log entry. The entry appears to the SIEM parser as two separate entries — one from the original logger, one forged by the attacker.

**Measured** (`.zen-batch-artifacts/batch-16/measure/01-crlf-log-injection.output.txt`): Python stdlib `logging.Formatter` with default settings and input `"alice\n14:12:00 CRITICAL user=admin action=privesc"` produced a two-line output: `07:12:13 INFO user=alice` followed by `14:12:00 CRITICAL user=admin action=privesc`. `line count: 2`. The JSON-encoding formatter emitted `line count: 1` — the `\n` was neutralized inside the JSON string.

**All-of preconditions:**
1. User-supplied input reaches a logger call.
2. The logger's formatter does not neutralize CR/LF/log-delimiter characters (e.g., default `logging.Formatter` in Python, `log.info("x: " + userInput)` concatenation in Java, raw `%s` substitution in C-style loggers).
3. The log consumer parses one entry per newline (common for plain-text log formats; also common for syslog RFC 6587 TCP framing).

**Attack recipe (reach + impact).**
```python
# Vulnerable Flask-shaped code
@app.route('/api/users', methods=['POST'])
def create_user():
    username = request.form.get('username', '')
    app.logger.info(f"User creation request: {username}")
    ...
```

Attacker submits `username=alice\n[CRITICAL] 03:14:15 PRIV action=role_grant user=attacker role=admin`. The log file reads:
```
[INFO] 03:14:14 User creation request: alice
[CRITICAL] 03:14:15 PRIV action=role_grant user=attacker role=admin
```

The forged `[CRITICAL]` line is indistinguishable from a legitimate privilege-grant event. If an incident response team reads logs during an investigation, they see a privilege grant that never occurred — or, more commonly, miss the attacker's real activity because the forged line fits a plausible-attacker-narrative.

**Confirmation signals.**
1. User input reaches a logger call via string concatenation or `%s`-style substitution.
2. The logger's formatter is plain-text (not JSON / structured).
3. A probe submitting `foo\n[FORGED-LINE]` produces two entries at the receiver.
4. Framework-default error handler logs the full request repr including unneutralized headers (Flask DEBUG=True; Spring Boot DEBUG level with `logging.pattern.console`).

**Mechanism routing.** The *log-channel expression* is owned here; the broader CRLF-injection mechanism (including non-log sinks like HTTP response headers) routes to `header_injection.md`. The underlying Log4j-specific CVE catalog (CVE-2026-34478 Rfc5424Layout, CVE-2026-34480 XmlLayout, CVE-2025-68161 / CVE-2026-34477 SocketAppender) is in `logging_alerting_failures_novel_deep.md`.

**Correct defense pattern.**
- Use structured logging (JSON) with `json.dumps`-based encoding — the formatter guarantees CRLF neutralization.
- Use Log4j 2.25.4+ with `Rfc5424Layout`'s `newLineEscape` explicitly set (post-rename).
- Use SLF4J MDC with Logback's `%replace(%msg){'[\r\n]','_'}` conversion rule for stubborn plain-text formats.
- Reject CRLF in user-controlled fields at the input-validation layer (OWASP ESAPI `ESAPI.encoder().encodeForLog`).

## Core Primitive — Secrets in Logs (CWE-532)

**Primitive.** Sensitive data (tokens, keys, passwords, PII, bearer tokens, cookies) is written to the log stream. Logs are typically retained longer than secrets; a token leaked to the log remains attacker-reachable after rotation. The log pipeline may replicate to multiple destinations (SIEM, backup, developer debug access), each a separate exposure surface.

**Measured** (`.zen-batch-artifacts/batch-16/measure/02-secrets-in-logs.output.txt`): a Flask-shaped error handler that logs the WSGI environ emits `Bearer sk-live-abcdef0123456789`, `api_key=live_XYZ_7777`, and `token=pat-abcdef12345` into the log sink. **3 secrets** reach the sink across two handler patterns. A careful handler that scrubs `HTTP_AUTHORIZATION` + `HTTP_COOKIE` + `QUERY_STRING` leaks **0 secrets** — the pattern is applicable.

**All-of preconditions:**
1. Secret-shaped data reaches a logger call (direct, or indirect via `request.repr()` / exception message / environ dump).
2. The logger's formatter does not scrub secret-shaped tokens.
3. The log stream reaches a persistence layer with retention longer than the secret's rotation period.

**Common sources.**
- Full-request repr in default error-handler stacks (Flask DEBUG; Spring Boot `AbstractErrorController`; Rails `ActionController::Base` on exception).
- URL query string containing API keys that get logged by access logs.
- Request bodies dumped on 500 responses.
- Exception messages that include database connection strings with embedded credentials.
- Debug-level loggers enabled in production.

**Confirmation signals.**
1. Grep SIEM for known secret-shaped patterns (`sk_live_`, `AKIA[0-9A-Z]{16}`, `ghp_`, Bearer, `password=`, `api_key=`). Non-zero hits are findings.
2. Default error-handler path dumps request state verbatim.
3. Access log format includes `$query_string` without filtering.
4. The project's log-retention policy exceeds the secrets' documented rotation period.

**Correct defense pattern.** Structured logging with explicit field allowlist (never log full-request-repr); regex-scrubbing middleware for the known secret-prefix patterns; separate access logs from application logs with different retention + ACL; application code calls `logger.info(event="user_login", user_id=user_id)` with explicit keys, never `logger.info(request_env)`.

## Core Primitive — Audit-Trail Tampering

**Primitive.** The audit trail is stored in a location the application role can modify or delete. Attacker who compromises the application reads the audit — then rewrites it to hide activity.

**All-of preconditions:**
1. Audit trail is stored in the same database as application data (common `audit_log` table).
2. The application's database role has DELETE / UPDATE privilege on the audit table.
3. No chain-of-custody / append-only / off-system write to a separate audit store.

**Attack recipe.** Attacker compromises app via any sink (RCE, SQL injection, privilege escalation). From the app's role: `DELETE FROM audit_log WHERE user_id = <attacker_id>` or `UPDATE audit_log SET action = 'login' WHERE action = 'role_grant'`. Audit history is now sanitized of the attacker's activity.

**Confirmation signals.**
1. Audit table shares the schema with application data; same DB role has access.
2. No separate audit-store write (e.g., no append-only S3 object-lock, no immutable Kinesis stream, no HSM-signed chain-of-custody).
3. Audit entries have no cryptographic integrity (no row-level HMAC, no append-only append-only chaining hash).

**Correct defense pattern.** Audit writes go to an append-only system external to the application: S3 object-lock bucket, Kinesis Firehose with retention, a separate database role with INSERT-only privilege, HSM-signed chain-of-custody blobs. The application role should have no DELETE/UPDATE on the audit table.

## Verification Discipline

- **Insufficient-logging claim**: show both the event occurring (via server behavior) AND the absence of a corresponding SIEM entry within the propagation SLA. A pre-production environment with reduced logging is NOT sufficient.
- **Missing-alerting claim**: fire the sequence that should trigger the alert; verify no page / Slack message / dashboard highlight within the alerting SLA. Confirm the alerting SLA is a documented operational contract, not an assumption.
- **CRLF log injection claim**: construct a probe payload with `\n[FORGED-LINE]` AND verify at the log receiver that two entries materialize (NOT just one entry with an embedded `\n`).
- **Secrets-in-logs claim**: grep the SIEM for the specific exposed value (if known) OR for the pattern class (e.g., `/sk_live_[A-Za-z0-9]{20,}/`); report hits with timestamp + source IP + user context.
- **Audit-trail-tampering claim**: inspect the audit storage's write/delete permission model; demonstrate (in sandbox) that the application role has DELETE/UPDATE on the audit table.

## Chaining

**Upstream (what grants the primitive).**
- An absent logging call in application code produces the insufficient-logging class.
- A WAF without rule-coverage for the event produces missing-alerting.
- A user-input sink that reaches the logger via concatenation produces CRLF injection.
- A permissive database role grants audit-trail-tampering reach.

**Downstream (what the primitive grants).**
- **Attacker dwell time extends.** Insufficient logging + missing alerting means the attacker is not detected during the attack window.
- **Attacker activity attribution becomes impossible.** CRLF injection + audit tampering mean post-incident forensics cannot reconstruct the sequence.
- **Secret leaks compound exposure.** Secrets-in-logs means a compromised secret has multiple exposure paths beyond the initial compromise.

**Composite chains.**
1. **CRLF log injection → attacker-authored "legitimate" log entries hide real attack.** The attacker's real activity (role grant, data export) is not logged OR is logged alongside forged lines that misdirect post-incident analysis.
2. **Secrets-in-logs → attacker reads logs → recovered secrets grant further compromise.** Routes to the credential-theft class (`authentication_jwt.md` for JWT secrets; `cloud/*` for cloud credentials; `information_disclosure.md` for the leak surface).
3. **Audit-trail tampering → attacker's prior activity is deleted → incident is scoped incorrectly.** Investigation misses the full compromise scope.

## Load this file when…

- A finding is about the detection pipeline rather than the exploitation primitive — "would the SIEM see this attack?"
- A log file includes user-controlled fields and the question is whether CRLF neutralization is in place.
- An audit trail is stored in the same database as application data (common OWASP A09 shape).
- A secret appeared in a log file; routing for cleanup and the broader exposure analysis starts here.
- Writing up a finding that is partly about absence-of-signal — OWASP A09:2025 category.

For the mechanism-level depth of log-injection beyond CRLF (format-string into log aggregators, NoSQL-shape injection into Elasticsearch, OTel-collector attribute injection), the injection mechanism is owned by the respective injection skill; this skill owns the detection-gap framing and the audit-trail discipline.

## Summary

Logging and alerting failures are the OWASP A09:2025 class covering five primitives: insufficient logging (CWE-778) where the auditable event is not recorded at all; missing alerting where the record exists but the operator doesn't learn in time; log injection / CRLF forgery (CWE-117) where user input corrupts the log channel to forge or hide entries; secrets-in-logs (CWE-532) where sensitive data lands in a retention-longer-than-rotation-window stream; and audit-trail tampering where the audit storage is reachable from the application role. The class is bounded — these are the primitives, and their mechanism-level depth is covered at full fidelity in the deep siblings. CVE catalog depth is thin because the vulnerability is often *absence* of a signal; where CVEs exist, they cluster on logging-library primitives (Log4j Rfc5424Layout CVE-2026-34478, SocketAppender hostname verification CVE-2025-68161 + CVE-2026-34477, XmlLayout CVE-2026-34480), owned in `logging_alerting_failures_novel_deep.md`. Confirmation discipline requires external test — fire the expected-to-be-logged event; check whether the SIEM sees it; check whether the alert reaches an operator — because the finding is about pipeline behavior, not code paths. Routing: log-injection mechanism beyond the log channel goes to the injection classes; audit-storage integrity goes to the authorization/role classes; secrets-in-logs cleanup routes to `information_disclosure.md`.
