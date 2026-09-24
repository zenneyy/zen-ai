---
name: weak-password-detection
description: Weak password detection, credential stuffing, password spraying, and brute-force testing across web/app and cloud IdP logins (Entra/M365, Okta), covering default and system-generated credentials, OTP and reset-token attacks, WebAuthn/passkey fallback abuse, password-field DoS and bcrypt truncation, and HTTP fuzzing / NSE brute-force tooling
---

# Weak Password Detection / Credential Brute-Force

Weak or default credentials remain one of the most prevalent and high-impact vulnerabilities. This skill covers systematic detection of weak passwords through dictionary attacks, credential stuffing, system-generated password prediction, and brute-force tooling.

## Attack Surface

- Login portals (web, API, mobile, SSH, FTP, Telnet, RDP)
- Admin panels, dashboards, and management interfaces
- Default or hardcoded credentials in applications and devices
- Self-registration flows with weak password policies
- Password reset flows that generate predictable tokens or passwords
- API key and token authentication with weak secrets

## Reconnaissance

### Identify Authentication Endpoints

- Standard login forms: `/login`, `/signin`, `/auth`, `/authenticate`, `/api/login`
- Admin panels: `/admin`, `/administrator`, `/manage`, `/console`, `/cpanel`
- API auth: `/api/v1/token`, `/oauth/token`, `/api/auth`, `/graphql` (login mutations)
- Service ports: SSH (22), FTP (21), Telnet (23), SMB (445), RDP (3389), MySQL (3306), PostgreSQL (5432), Redis (6379), MongoDB (27017)
- Mobile app login endpoints and deep-link auth handlers

### Determine Authentication Mechanism

- Form-based (POST with username/password fields)
- Basic Authentication (Base64 `Authorization: Basic ...`)
- Bearer token / JWT (password grant flow)
- API key in header, query parameter, or body
- Multi-step authentication (username first, then password)
- CAPTCHA presence and type (reCAPTCHA, hCaptcha, image-based, math)
- Rate limiting indicators (429 responses, lockout messages, delays)

### Enumerate Valid Usernames

- Error message differentiation: "Invalid username" vs "Invalid password"
- Registration page username availability checks
- Password reset flow: response timing or message leakage
- Public profiles, API responses, or metadata exposing usernames
- Common patterns: `admin`, `administrator`, `root`, `user`, `test`, `guest`, `support`, `service`, `api`, `dev`, `ops`
- Email format derivation from company domain patterns

Enumeration oracles (a valid vs invalid user must differ in *something*):

- **Message/status**: distinct text or code for unknown user vs wrong password.
- **Response length / structure**: even "generic" errors often differ by a few
  bytes, a field, or a redirect between the two cases — diff them.
- **Timing**: a valid user path runs the password hash (slow); an unknown user
  short-circuits (fast). Measure the delta over many samples; it is a real
  oracle even when the message is identical.
- **Side flows**: registration "already taken", password-reset "email sent"
  vs "no account", and MFA-enrollment prompts each leak existence.
- **Dedicated IdP endpoints** (no lockout, purpose-built for enum):
  Microsoft `GetCredentialType`
  (`https://login.microsoftonline.com/common/GetCredentialType`, returns
  `IfExistsResult`), Okta `/api/v1/users` and `/api/v1/authn` status, AWS
  Cognito `InitiateAuth`/`ForgotPassword` error differences.

```bash
# length/timing diff harness — flag users whose response deviates from the invalid baseline
ffuf -w users.txt:USER -u https://target/login -X POST \
  -d 'username=USER&password=Wrong123!' -H 'Content-Type: application/x-www-form-urlencoded' \
  -mode clusterbomb -of json -o enum.json -ac        # -ac auto-calibrates the invalid baseline
# then triage by 'duration' (timing oracle) and 'length' fields in enum.json
```

## Key Vulnerabilities

### Weak Password Policies

- No minimum length or complexity requirements
- Allowing common passwords: `password`, `123456`, `qwerty`, `admin`, `letmein`
- Not checking against breached password databases (Have I Been Pwned)
- Case-insensitive password storage
- No password history enforcement
- Excessively short maximum length (indicates plaintext or weak hashing)

### Default and Hardcoded Credentials

- Vendor defaults: `admin/admin`, `admin/password`, `root/root`, `guest/guest`
- Application frameworks: `django/admin`, `tomcat/tomcat`, `weblogic/weblogic`
- IoT devices, routers, cameras: manufacturer-specific defaults
- Database defaults: `postgres/postgres`, `sa/sa`, `root/(empty)`
- Cloud defaults: AWS instance metadata, Azure default service principals
- Hardcoded in source code, configuration files, or documentation

### Credential Stuffing

- Users reuse passwords across services
- Breached credential lists (COMB, Collection #1-5, etc.) enable mass account takeover
- No multi-factor authentication allows direct access with valid credentials
- Missing breach detection or forced password rotation after known leaks

### Predictable System-Generated Passwords

- Sequential or pattern-based: `Password1`, `Welcome2025!`, `CompanyName123`
- Time-based generation: passwords derived from registration timestamp
- Weak randomness: predictable PRNG seeds in password generators
- Reset tokens that double as temporary passwords with short expiration

### Brute-Force Vulnerabilities

- No rate limiting on login attempts
- Absent or ineffective account lockout (client-side only, easily bypassed)
- IP-based blocking without session/user correlation (rotate IPs via proxy)
- CAPTCHA bypassable or only triggered after excessive attempts
- Parallel login attempts not tracked (race conditions on attempt counters)
- Verbose error messages revealing valid usernames

### Password-Field Denial of Service and Truncation

The password field is an unauthenticated compute sink and, with bcrypt, a
truncation surface:

- **Long-password CPU DoS** — if the server hashes the raw password with a
  slow KDF (bcrypt/scrypt/argon2/PBKDF2) before length-checking, a very large
  password string burns CPU per request. POST a multi-hundred-KB password to
  the login/registration endpoint and watch latency climb; a handful of
  concurrent requests can exhaust workers. The fix (and the thing to verify)
  is a hard max length (commonly ~72–128 chars) enforced *before* hashing, or
  a fast pre-hash (SHA-256) fed into bcrypt.
- **bcrypt 72-byte truncation** — bcrypt only consumes the first 72 bytes of
  its input. Two consequences to test: (1) any password sharing the same first
  72 bytes authenticates, so a known long prefix plus arbitrary suffix works;
  (2) when an app concatenates fields before bcrypt (e.g. `username+password`
  or `pepper+password`), a long left field can push the real password past the
  72-byte boundary so it is ignored — an authentication-bypass class in
  delegated-auth/LDAP designs. Probe by registering a >72-byte password and
  logging in with the same first 72 bytes plus a different tail.

## Advanced Techniques

### Targeted Password Lists

- Generate custom wordlists from:
  - Company name, product names, and domain components
  - Geographic location, industry terms
  - Season + year patterns: `Summer2025!`, `Winter2026@`
  - Keyboard walks and leet speak variations
  - Previously breached passwords for the target domain
- Scrape the target site to build a content-derived wordlist (e.g. a small custom Python crawler that harvests unique words)

### Credential Stuffing Workflows

- Use breach databases filtered by target domain or related domains
- Test email:password pairs where email matches target domain
- Test username:password pairs with common username derivations
- Validate successful logins without triggering MFA by checking session endpoints

### Rate-Limit and Lockout Bypass

Identify which counter the control keys on, then break that key:

- **Per-IP** → rotate source IPs (FireProx / API-Gateway rotation, proxy pool)
  or spoof forwarding headers the app trusts: `X-Forwarded-For`, `X-Real-IP`,
  `True-Client-IP`, `CF-Connecting-IP` (a fresh value each request). Load
  `header_injection` for the trust-boundary detail.
- **Per-account** → spray (one password, many accounts) instead of brute
  (many passwords, one account); the per-account counter never trips.
- **Per-username-string, not per-identity** → the counter often keys on the
  raw submitted string, so a username variant that authenticates the same
  account but hashes to a different key evades it: trailing space/dot, case
  change (`Admin` vs `admin`), unicode-equivalent, `admin ` / `admin%00`,
  or email `+tag`. Test whether the variant still logs in.
- **Counter reset side-channels** → requesting a password reset, a new OTP, or
  a new session token sometimes clears the attempt counter; a successful login
  from another account may reset a shared bucket.
- **Step-separated counters** → in multi-step auth the password step and the
  2FA/OTP step frequently have independent (or missing) counters — brute the
  step that isn't guarded.
- **Concurrency/race** → fire N attempts in parallel (HTTP/2 multiplexing) so
  they all read the counter before any increments it; load `race_conditions`.
- **Client-side or soft controls** → JS-only lockout, a `429` with no real
  backend enforcement, or a lockout that lifts in seconds — confirm the control
  actually blocks the credential check, not just the UI.

### Multi-Step Authentication Bypass

- Username enumeration → password brute-force on second step
- Session fixation between steps: manipulate step identifiers
- Skip steps via direct URL access to later stages
- Response manipulation to bypass verification checks

### API and Mobile-Specific

- GraphQL login mutations: batch brute-force via array inputs
- Mobile APIs often lack rate limiting compared to web frontends
- JWT password grant flows: brute-force against `/token` endpoint
- OAuth2 password grant: test `grant_type=password` with weak credentials

### Cloud / IdP Password Spraying

Cloud identity providers are the highest-yield spray target: one weak
password across a large user set, and lockout is usually per-account
"smart lockout" (a few bad attempts per account per ~10–30 min window) that
you defeat by spraying **one password across all users, then waiting the
window** — never many passwords against one user.

- **Microsoft Entra ID / Microsoft 365** — endpoints and tools:
  ```bash
  # Enumerate valid users (no lockout) via GetCredentialType / Autologon
  o365spray --validate --domain target.com
  o365spray --enum --userfile users.txt --domain target.com
  # Spray one password against the enumerated users
  o365spray --spray --userfile valid.txt --password 'Autumn2026!' --domain target.com --rate 10 --delay 60
  # MSOLSpray (login.microsoftonline.com) — reports MFA/locked/disabled per hit
  # TREVORspray — smart, supports SSH-proxy/subnet rotation and ADFS
  trevorspray -u users.txt -p 'Autumn2026!' --ssh user@proxy1 user@proxy2
  ```
  Test all front doors: `login.microsoftonline.com`, Autodiscover
  (`autodiscover-s.outlook.com`), ADFS (`/adfs/ls`), and Azure AD Graph — they
  can have different lockout and MFA enforcement.
- **Okta** — `/api/v1/authn` returns rich status (`SUCCESS`, `LOCKED_OUT`,
  `MFA_REQUIRED`, `PASSWORD_EXPIRED`); spray with a low rate and read status.
- **Google Workspace / others** — SAML/OIDC front doors and any legacy
  ROPC/basic-auth endpoint that bypasses the interactive MFA path.
- **IP rotation to defeat per-IP throttling**: **FireProx** stands up an AWS
  API Gateway that rotates the source IP on every request; point the spray
  tool's proxy at it. `omnispray` is a modular framework wrapping many of the
  above.
- Cadence: 1–2 attempts per account per lockout window, jittered, business
  hours to blend in. Track which accounts are locked and skip them.
- For on-prem AD/Kerberos/SMB spraying (`kerbrute passwordspray`, NTLM over
  SMB), load `active_directory` — that is a different lockout and enumeration
  model.

### OTP and Reset-Token Attacks

The one-time-code and reset flows are frequently weaker than the password:

- **OTP brute-force** — 4–6 digit codes have a tiny keyspace. Test whether the
  code is attempt-bound (a fixed code per session that you can hammer),
  rate-limited per code vs per account, invalidated after N failures, and
  whether parallel/racing requests bypass the counter. Response-shape or
  status-code differences between right and wrong digits leak progress.
- **Rate-limit bypass on OTP**: rotate IP (FireProx), reset the counter by
  requesting a new code mid-brute, or switch transport (mobile API vs web).
- **Reset-token entropy** — capture several reset tokens and analyze: sequential
  IDs, timestamp-seeded values, short/low-entropy tokens, or tokens that double
  as temporary passwords. Predictable tokens = account takeover without the
  email.
- **Magic-link brute / reuse** — links that never expire, are reusable, or
  carry a guessable token.
- **Host-header reset poisoning** — the reset link is built from a spoofable
  `Host`/`X-Forwarded-Host`, sending the victim's token to your domain. Load
  `header_injection` for that chain.

### WebAuthn / Passkeys / FIDO2

Passkeys are phishing-resistant public-key credentials — you cannot brute-force
or credential-stuff them, and a password spray against a passkey-only account
is a non-finding. The weaknesses are around them, not in them:

- **Recovery / fallback downgrade** — the account-recovery path (email link,
  SMS OTP, security questions, or a still-enabled password) is the real target.
  If a passkey account can be recovered with a weaker factor, spray/brute that
  factor instead and treat the passkey as bypassed.
- **Registration binding** — the passkey *registration* ceremony is a
  state-changing action; test it for IDOR/CSRF that lets you bind *your*
  authenticator to a victim account (adding a credential you control).
- **`userVerification: discouraged`** or a missing UV check turns the passkey
  into single-factor possession; note it.
- **RP ID / origin validation** — verify the server checks the `origin` and
  `rpId` in the attestation/assertion; a lax check can allow cross-origin
  ceremonies.
- **Credential-exclusion and enumeration** — registration/`get` responses can
  leak whether an account has a credential (user enumeration).

### Service-Level Brute-Force

- HTTP login endpoints: `ffuf` or custom scripts (see Tooling)
- SSH/FTP/SMB/Telnet and other services: `nmap` NSE `*-brute` scripts, e.g. `nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt target.com`
- Databases (MySQL, PostgreSQL, MongoDB, Redis): weak/default credentials via the matching NSE brute script (`mysql-brute`, `pgsql-brute`, `mongodb-brute`, `redis-brute`) or a custom client script
- Any protocol lacking a ready script: custom Python

## Tooling

### ffuf (primary for web logins)

- Login brute-force with multiple users and passwords:
  `ffuf -w users.txt:USER -w passwords.txt:PASS -u https://target.com/login -X POST -d "username=USER&password=PASS" -fr "Invalid"`
- JSON body / custom headers via `-H` and a JSON `-d` payload
- Filter by response size, status code, or regex to identify successes

### nmap NSE (service brute-force)

- `*-brute` scripts cover many non-HTTP services:
  `nmap -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords.txt target.com`
- Available scripts include `ssh-brute`, `ftp-brute`, `smb-brute`, `telnet-brute`, `mysql-brute`, `pgsql-brute`, `mongodb-brute`, `redis-brute`, `http-brute`, `http-form-brute`.

### Custom Python Scripts

- Use `requests` with threading for high-speed API brute-force
- Implement jitter and proxy rotation to evade rate limiting
- Parse CSRF tokens dynamically between requests

### Cloud / IdP Spraying

- **o365spray** / **MSOLSpray** / **TREVORspray** — Entra/M365 user enum + spray (invocations above). TREVORspray adds SSH-proxy/subnet source rotation and ADFS support.
- **omnispray** — modular spray framework (pluggable enum/spray modules per IdP).
- **FireProx** — stands up an AWS API Gateway that rotates the source IP per request; front any HTTP brute/spray through it to defeat per-IP rate limits:
  ```bash
  python fire.py --access_key ... --secret_access_key ... --region us-east-1 \
    --command create --url https://login.microsoftonline.com
  # then point the spray tool's --proxy / URL at the returned API Gateway URL
  ```

### Classic Service Brute-Forcers

Not installed in the default sandbox (install via apt/pipx when the task needs
them and network reachability exists); use for the non-HTTP services where
`ffuf`/NSE are awkward:

- **hydra** — broad protocol coverage: `hydra -L users.txt -P pass.txt ssh://target` (also `ftp`, `smb`, `rdp`, `http-post-form`, `mysql`, `postgres`, ...).
- **medusa** — parallel equivalent: `medusa -h target -U users.txt -P pass.txt -M ssh`.
- **patator** — scriptable, precise response filtering: `patator http_fuzz url=https://target/login method=POST body='u=FILE0&p=FILE1' 0=users.txt 1=pass.txt -x ignore:fgrep='Invalid'`.

### Wordlists

No password wordlists ship in the sandbox by default — download what you need into `/home/pentester/tools/wordlists` at runtime:
- Common passwords (e.g. `rockyou.txt`) from its upstream source
- SecLists `Passwords/` and `Passwords/Default-Credentials/` (vendor defaults) from https://github.com/danielmiessler/SecLists
- Custom lists from target-specific scraping
- Breach compilation subsets filtered by target relevance

## Validation

1. Confirm successful login with captured credentials (session token, cookie, or JWT)
2. Verify account access level: admin vs user privileges
3. Check if MFA is enforced post-login or can be bypassed
4. Test credential reuse across other endpoints or services
5. Document password policy weaknesses that allowed the breach
6. Verify if the same credentials work on staging, dev, or related domains

## False Positives

- Honey accounts or honeypot responses designed to mislead attackers
- Temporary lockouts that resolve quickly (distinguish from permanent bans)
- Different error messages that don't actually indicate valid username enumeration
- CAPTCHA or WAF blocking that appears as a failed login
- Rate limiting that returns 429 instead of 401 (adjust timing)

## Impact

- Complete account takeover for affected users
- Administrative access leading to full system compromise
- Lateral movement via reused credentials across services
- Data exfiltration, privilege escalation, and persistence
- Reputational damage and compliance violations (GDPR, PCI-DSS)

## Pro Tips

1. Always start with default credentials and vendor-specific lists before broad brute-force
2. Enumerate usernames first; password brute-force without valid users is inefficient
3. Use small, targeted wordlists before massive lists like rockyou.txt
4. Monitor for rate limiting and adapt delays; aggressive brute-force causes IP bans and alerts
5. Test for password spraying (one password, many users) before targeted brute-force
6. Check for concurrent session limits; successful logins may kick out legitimate users
7. GraphQL batching can test multiple credentials in a single request, bypassing per-request limits
8. Document the password policy and recommend minimum standards (length, complexity, breach checking)
9. For web logins prefer `ffuf`; for other services use `nmap` NSE `*-brute` scripts or custom scripts with equivalent logic
10. Combine with MFA testing: weak passwords plus missing MFA is a critical finding

## Summary

Weak password detection requires systematic enumeration of authentication surfaces, intelligent wordlist selection, and careful brute-force execution. The highest impact often comes from default credentials, password spraying, and credential stuffing rather than exhaustive brute-force. Always validate findings with confirmed logins and assess the full scope of account compromise.
