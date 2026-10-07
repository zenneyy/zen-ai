---
name: fp-taxonomy
description: Cross-class false-positive taxonomy with per-shape discriminators — the recurring FP patterns aggregated from the vulnerability corpus, canonicalized into one reference.
---

# False-Positive Taxonomy

False positives recur in structural shapes that cross vulnerability
class boundaries. The same FP pattern — echo-back, silent 2xx-empty,
auto-scoping, OAST source-IP mismatch — appears in SQLi, SSRF, IDOR,
SSTI, and a dozen other classes. This skill canonicalizes those
shapes into one taxonomy with a concrete discriminator for each.

The per-class falsification move (what disproves a specific class's
finding) lives in `validation/red_team_the_finding`. The negative
control design (the baseline that must not trigger) lives in
`validation/negative_control_design`. This file owns the structural
FP shapes that apply across classes.

## How to Use This Taxonomy

When a finding produces an ambiguous signal, check it against this
taxonomy before confirming. Each shape has:

- **Pattern**: what the FP looks like.
- **Discriminator**: the specific test that distinguishes the FP
  from a real finding.
- **Classes affected**: which vulnerability classes exhibit this
  shape.

If your signal matches a shape, run the discriminator. If the
discriminator confirms the FP, close the candidate. If it does not,
the finding survives.

---

## Shape 1: Echo-Back / Reflection

**Pattern**: the target echoes the injected payload back in the
response without evaluating it through the vulnerable sink. The
response *contains* the payload but the sink never *processed* it.

**Discriminator**: vary the payload. If `payload_A` and `payload_B`
both appear literally in the response but produce no behavioral
difference (no result-set change, no computation, no file read, no
outbound request), the input is reflected, not evaluated. The
signal is in the *effect*, not the echo.

**Classes affected**: SQL injection (error pages echoing input),
SSRF (URL reflected but not fetched), SSTI (`{{7*7}}` rendered
literally), SSJI (printf/format-string reflecting `7*7` as-is),
XPath injection (payload in response body with no result-set
change), XSLT injection (XSLT bytes reflected without execution),
XXE (DOCTYPE fragment echoed in error message), LDAP injection
(500 with input literal), prototype pollution (polluted key visible
in JSON echo but never merged), path traversal (payload echoed but
not file bytes), header injection (headers vary but correctly
keyed), NoSQL injection (validation errors, not operator execution),
semantic confusion (parser accepts odd syntax but downstream
preserves safe meaning), web cache poisoning (one-shot reflection,
not cached poisoning).

## Shape 2: Silent 2xx-Empty

**Pattern**: the target returns a 2xx response (often 200 OK) but
no actual state change or data exposure occurred. The endpoint
accepted the request syntactically but did not act on it.

**Discriminator**: follow up the probe with a read/state-check
request to confirm whether the action actually mutated backend
state. A 200 without a verified state change is not a finding.
Compare the returned data against the expected state, not just the
HTTP status.

**Classes affected**: BFLA (2xx-empty on foreign admin actions —
silent enforcement), IDOR (empty array/null for another user's
resource), CSRF (200 with no state change — token required in header
the PoC didn't send), mass assignment (server recomputes derived
fields, ignoring client input), path traversal (200 with empty body
on both control and traversal), race conditions (visual-only glitch
without durable state change), business logic (visual-only
inconsistency).

## Shape 3: Auto-Scoping / Self-Coercion

**Pattern**: the API silently coerces the request back to the
caller's own scope. The request looks like it accessed a foreign
resource, but the returned data belongs to the caller, not the
target.

**Discriminator**: check the returned data's identifier and owner
fields against the *target* account's known values. If the
response body contains the caller's own ID/data rather than the
target's, the server auto-scoped. The IDOR confirmation predicate's
third clause exists to reject this shape.

**Classes affected**: IDOR (response with different identifier —
server coerced to caller's scope), BFLA (response includes only
public/generic content), business logic (client-side limit
re-enforced server-side on commit), mass assignment (returned object
includes the field but database-level trigger resets it).

## Shape 4: Scanner / WAF Artifacts

**Pattern**: a security scanner, WAF, or automated tool generates
the signal rather than the application under test. The finding is
an artifact of the testing infrastructure.

**Discriminator**: identify the signal source — check source IPs
against known scanner ranges, check User-Agent strings, check
timing patterns (scanners are typically <100ms; app-side responses
are variable). Separate scanner-generated OAST traffic from your own
by minting per-run OAST hosts.

**Classes affected**: SQL injection (sqlmap "possibly injectable"
without confirmed channel; WAF block pages with SQL-shaped rule
names), XXE (OAST hit from background scanner in target's network),
insecure deserialization (callback from scanner-constructed URLDNS),
weak password (CAPTCHA or WAF blocking appearing as failed login),
NoSQL injection ($where visible in error but rejected at driver
layer).

## Shape 5: OAST Source-IP Mismatch

**Pattern**: an OAST callback arrives but from the tester's own IP
(or the client's browser), not from the target's server-side egress
IP. The browser or frontend JS made the request, not the backend.

**Discriminator**: compare the OAST callback source IP to the
target's known egress IP. A match with the tester's machine or
browser IP confirms client-side fetch. This applies to every
callback-based finding.

**Classes affected**: SSRF (client-side fetch, not server-side),
SQL injection (client-side JS fired callback), XXE (DNS callback
without HTTP fetch — URI validation, not entity resolution), path
traversal/RFI (DNS callback from URL-parser resolution, not fetch).

## Shape 6: Timing Noise / Non-Scaling Delays

**Pattern**: a response delay occurs but does not scale with the
injected parameter, or is caused by network/infrastructure factors.

**Discriminator**: the delay must *scale* with the injected
parameter across ≥3 retries. `SLEEP(1)` → ~1s; `SLEEP(5)` → ~5s.
Measure against a control request from the same client, same route,
same time bucket. A single slow response is not confirmation.

**Classes affected**: SQL injection (network, CPU, rate limiters,
background jobs), race conditions (benign interleaving that looks
like a win), browser security (timing oracle with no measured
separation beyond noise), business logic (race-window that never
closes within attacker timing), cryptographic failures (timing
attack with insufficient samples), DoS/ReDoS (slow endpoint at
baseline load).

## Shape 7: Present-but-Hidden Data

**Pattern**: the data exists and might be reachable in some context,
but the target's access controls correctly prevent the tested
identity from reaching it.

**Discriminator**: confirm the authorization check is consistently
enforced across all channels, encodings, and API versions. A
correctly-gated resource is not a finding. The resource's
existence is not the vulnerability — the missing gate is.

**Classes affected**: IDOR (public/anonymous resources by design;
correct row-level checks enforced), information disclosure
(intentional public docs), BFLA (read-only endpoints mislabeled as
admin but publicly documented), CORS (endpoint returns no
user-identifiable content), clickjacking (X-Frame-Options: DENY
enforced).

## Shape 8: Role-Echo / Authorization Correctly Enforced

**Pattern**: the endpoint exists and responds, but the authorization
model correctly restricts the action. The test confirms the control
works, not that it is bypassed.

**Discriminator**: verify the response does not contain data from
the target principal. A 403, 401, or empty response is evidence of
working authorization, not a finding.

**Classes affected**: IDOR (correct row-level checks), BFLA
(simulated environments with stubbed admin endpoints), CORS
(Allow-Origin: * but no Allow-Credentials), CSRF (token
verification present), authentication/JWT (strict audience/issuer
enforcement), open redirect (redirects constrained to relative
same-origin paths).

## Shape 9: Cache Warmup / Cache-Key Confusion

**Pattern**: a cached response appears to contain
attacker-influenced content, but the cache key correctly includes
the varying input, or the cache TTL is too short to produce impact.

**Discriminator**: send two requests with different header/parameter
values and check for independent cached responses. If the responses
are independently keyed, the cache is working correctly. Also verify
the TTL is non-trivial.

**Classes affected**: web cache poisoning (response cached but
header IS keyed; TTL=0), header injection (headers correctly
keyed), IDOR (cache hit of a public resource under odd key), SSRF
(cache/CDN differentials leaking HIT/MISS).

## Shape 10: Sandbox / Isolation Effective

**Pattern**: the vulnerable primitive exists but is executed within
an effective sandbox that prevents exploitation.

**Discriminator**: verify the sandbox thoroughly — sandboxes leak.
Check network/exec/IO primitives within the sandbox. A sandbox with
`--capabilities=SYS_ADMIN` or `--privileged` is not a sandbox. The
finding may downgrade to informational (sandbox escape is the real
finding).

**Classes affected**: insecure deserialization (isolated sandbox),
SSJI (formula engines with bounded grammar), RCE (restricted VM),
insecure file uploads (locked-down converter sandbox), SSTI
(SandboxedEnvironment with no request/config in context), LLM
prompt injection (sandboxed tools), agentic system security (runtime
credential/network policy prevents access).

## Shape 11: Wrong-Sink Routing

**Pattern**: the payload triggers a response, but the underlying
sink is a different vulnerability class than the one being tested.

**Discriminator**: check the error message or response for
signatures of the actual sink. Route the finding to the correct
class file. The finding may still be real — just not the class you
thought.

**Classes affected**: LDAP injection (SQL error on LDAP payload —
sink is SQL), XPath injection (SQL error on XPath payload), XSLT
injection (msxsl:script payload against non-.NET backend), SSJI
(JavaScript response but client-side evaluation — this is XSS),
SSTI (client-side template engine — client-side template injection,
not SSTI), NoSQL injection (MongoBleed is not NoSQLi — it is a zlib
memory-disclosure flaw).

## Shape 12: Version/Platform Mismatch

**Pattern**: the payload or technique applies to a different
version, platform, or configuration than the one deployed.

**Discriminator**: fingerprint the target's exact version and
configuration before firing version-specific payloads. Verify
preconditions are met on the actual deployment.

**Classes affected**: SSRF (alternate IP forms against Go fetchers
— Go rejects forms that work in curl), XSLT injection (extension
RCE without processor+version anchor), argument injection
(option exists on another release but not the deployed one),
semantic confusion (version-specific behavior claimed as universal),
CSRF (SameSite=Lax in prod but None in staging), DoS
(hash-flooding claim on framework migrated to SipHash), prototype
pollution (lodash 4.17.21 does not pollute).

## Shape 13: Dead-Code / Unreachable Sink

**Pattern**: the vulnerable code pattern exists in the codebase but
is unreachable from attacker-controlled input.

**Discriminator**: trace from the user-controlled input to the
sink. If the code path is dead (`if False:` branch, unreachable
helper, test-only fixture), unreferenced, or guarded by an earlier
check, the finding is a code-quality observation, not a
vulnerability. In white-box mode, this is a `source_aware_discovery`
concern — the grep hit is real; the exploitability is not.

**Classes affected**: insecure deserialization (pickle/Marshal in
dead code), DoS/ReDoS (regex unreachable from input), agentic
system security (listed tool cannot be invoked by tested identity),
email header injection (CRLF-reflected field not reaching mail
composition), LLM prompt injection (model says it will act but no
privileged sink), SQL injection (pattern match in comment/test
fixture/vendored dependency).

## Shape 14: Mitigation-Effective

**Pattern**: a deployed defense mechanism effectively prevents
exploitation even though the underlying pattern exists.

**Discriminator**: confirm the defense is consistently enforced
across all paths, methods, and encodings. A defense that works on
one path but not another is a bypass finding, not an FP. Test at
least one bypass technique before concluding the defense holds.

**Classes affected**: XSS (CSP with nonces/hashes, Trusted Types,
DOMPurify strict mode), clickjacking (X-Frame-Options DENY, CSP
frame-ancestors none), CORS (SameSite=Strict cookies for auth),
CSRF (token verification present, SameSite=Strict), open redirect
(strict pre-registered OAuth redirect_uri), prototype pollution
(parser strips __proto__, framework uses Object.create(null)), SSRF
(strict allowlists with DNS pinning, no redirect following), HTTP
request smuggling (WAF normalizing TE/CL headers).

## Shape 15: Cryptographic / Integrity Gate Effective

**Pattern**: the payload is protected by a cryptographic integrity
check the attacker cannot bypass without the key.

**Discriminator**: verify the key has not leaked, the verification
is consistently applied, and the integrity check covers the full
payload. Check for key-management issues that shift the finding to
a different class (information_disclosure for key leakage).

**Classes affected**: insecure deserialization (blob encrypted or
signed with verified HMAC and key not leaked; ViewState with
enableViewStateMac=true and machine key neither leaked nor default),
authentication/JWT (signature verified but claim ignored —
authorization reads from session store, not token), cryptographic
failures (length-extension claim on HMAC — HMAC's double-hash
construction prevents extension).

---

## Using the Taxonomy in Practice

When you encounter an ambiguous signal:

1. Identify which shapes could explain it — scan the shapes above
   for a pattern match.
2. Run the discriminator for each candidate shape.
3. If a discriminator confirms an FP shape, close the candidate
   with the shape name and the discriminator result in the
   `counterevidence` field.
4. If no discriminator confirms an FP, the signal survives and the
   finding proceeds to `validation/blind_revalidation`.

Cross-reference: `validation/red_team_the_finding` for per-class
falsification moves. `validation/negative_control_design` for the
control request methodology. `analysis/counterevidence` for closure
discipline.
