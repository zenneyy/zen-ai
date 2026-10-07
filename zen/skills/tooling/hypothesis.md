---
name: hypothesis
description: Property-based local differential testing with Hypothesis for parsers, canonicalizers, serializers, validators, routers, and other pure functions, emphasizing explicit invariants, shrinking, reproducibility, and bounded resource use
---

# Hypothesis Security-Research Usage Guide

[Hypothesis](https://hypothesis.readthedocs.io/) is a property-based testing and fuzzing library for Python. In security research it finds parser differentials, canonicalization bugs, serialization edge cases, and state-machine violations that handwritten test vectors miss — by generating inputs from strategy-defined distributions and shrinking failures to minimal counterexamples.

Use Hypothesis when a security property can be expressed over local code and failures are likely to hide in combinations of encoding, normalization, structure, or parser recovery. It is especially useful for comparing two implementations or checking that validation and consumption preserve the same meaning.

Do not point unrestricted generators at a live service. Hypothesis is safest and most useful against pure local adapters with no network, subprocess, filesystem, or persistent-state side effects.

Official project: [Hypothesis](https://github.com/HypothesisWorks/hypothesis)

## Install in the Sandbox

Hypothesis is **not pre-installed** in the 1.2.2 sandbox image. The sandbox proxy environment routes all traffic through Caido, which blocks PyPI — unset the proxy variables before installing:

```bash
unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY
uv pip install --python /app/.venv/bin/python hypothesis
```

This installs `hypothesis` 6.168.5 (and its dependency `sortedcontainers`). Verify:

```bash
python3 -c "import hypothesis; print(hypothesis.__version__)"
```

For reproducible engagements, pin the version:

```bash
uv pip install --python /app/.venv/bin/python 'hypothesis==6.168.5'
```

Install once per container session. The install persists for the container's lifetime but not across restarts.

## Start From an Invariant

Write the security relationship before writing strategies. The invariant is the claim — Hypothesis generates the inputs that try to break it.

Core patterns:

```text
allowlist(raw) accepts  →  sink(canonicalize(raw)) stays inside the allowed origin/path/type
validator(raw) accepts  →  consumer(raw) assigns the same semantics (media type, auth level, scope)
parse_A(raw) and parse_B(raw)  →  agree on message boundaries and authoritative fields
serialize(parse(raw))  →  cannot introduce a new delimiter, wildcard, traversal segment, or field
decode(encode(raw))  →  round-trips to the original value (no data loss, no injection surface)
hash(normalize(raw)) == hash(raw)  →  normalization does not create collisions across trust boundaries
```

More security-specific invariant shapes:

```text
url_parse(crafted).hostname  →  matches the allowlist check's hostname (SSRF differential)
jwt_decode(jwt_encode(claims))  →  returns the same claims with no extra fields (token forgery)
path_normalize(traversal)  →  never resolves above the root (LFI escape)
header_parse(raw).get("Host")  →  matches what the routing layer sees (request smuggling)
deser(ser(obj))  →  does not instantiate types outside the allowed set (deser gadget)
acl_check(request, role)  →  consistent across the middleware chain (authz bypass)
```

A test that only checks "does not crash" finds robustness bugs but does not establish a security differential. Always state the boundary the invariant protects.

## Strategies API for Security Inputs

Hypothesis strategies generate values from defined distributions. The security-relevant strategies and their research applications:

### Encoding and text attacks — `st.text`, `st.binary`, `st.characters`

```python
from hypothesis import strategies as st

ascii_with_nulls = st.text(
    alphabet=st.characters(categories=("L", "N", "P", "Z", "C")),
    max_size=256,
)

unicode_edge_cases = st.text(
    alphabet=st.characters(
        categories=("L", "M", "N", "P", "S", "Z"),
        include_characters="\x00\r\n\x0b\x0c\x85  ﻿￾",
    ),
    min_size=1,
    max_size=128,
)

raw_bytes = st.binary(min_size=1, max_size=512)
```

Use `st.text` for string-level parser testing — URL paths, header values, JSON keys, query parameters. Use `st.binary` for byte-level protocol testing — serialized payloads, binary formats, truncated frames. `st.characters` controls the Unicode categories and specific codepoints in the alphabet — inject null bytes, CRLF, Unicode line/paragraph separators, BOMs, replacement characters.

### Grammar-constrained fuzzing — `st.from_regex`

```python
path_segments = st.from_regex(
    r"/([a-zA-Z0-9_.~%-]{1,32}|\.\.){1,8}", fullmatch=True
)

header_values = st.from_regex(
    r"[^\r\n\x00]{1,256}", fullmatch=True
)

sql_fragments = st.from_regex(
    r"(\'|\"|\-\-|;|/\*|\*/|OR |AND |UNION |SELECT )[a-zA-Z0-9 ]{0,32}",
    fullmatch=True,
)
```

`st.from_regex` generates strings matching a regex pattern. Use `fullmatch=True` to anchor the entire string. This bridges the gap between pure random bytes (too noisy) and handwritten vectors (too narrow) — it produces structurally valid inputs with adversarial content.

### Structured security payloads — `st.builds`, `st.composite`

```python
@st.composite
def jwt_payloads(draw):
    header = draw(st.fixed_dictionaries({
        "alg": st.sampled_from(["HS256", "RS256", "none", "HS384"]),
        "typ": st.just("JWT"),
    }))
    claims = draw(st.fixed_dictionaries({
        "sub": st.text(min_size=1, max_size=32),
        "role": st.sampled_from(["user", "admin", "service", ""]),
        "exp": st.integers(min_value=0, max_value=2**32),
    }))
    return header, claims


http_requests = st.builds(
    dict,
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]),
    path=st.from_regex(r"/[a-z/]{1,64}", fullmatch=True),
    headers=st.dictionaries(
        keys=st.sampled_from(["Host", "Content-Type", "Authorization", "X-Forwarded-For"]),
        values=st.text(max_size=128),
        max_size=4,
    ),
)
```

`st.composite` draws from other strategies inside a function — use it for payloads where fields are interdependent (the algorithm determines the signing key). `st.builds` constructs an object from strategy-generated arguments — use it for flat structures.

### Injection token mixing — `st.sampled_from`, `st.one_of`

```python
injection_tokens = st.sampled_from([
    "'", "\"", ";", "--", "/*", "*/", "||", "&&",
    "${", "{{", "}}", "<", ">", "`", "|", "\n",
    "\r\n", "\x00", "%00", "%0d%0a", "../", "..\\",
])

mixed_input = st.one_of(
    st.text(max_size=64),
    injection_tokens,
    st.from_regex(r"[a-z]{1,8}" + r"['\";|<>`]" + r"[a-z]{0,8}", fullmatch=True),
)
```

`st.sampled_from` picks from a fixed list — use it for known-bad tokens. `st.one_of` switches between multiple strategies — use it to mix benign and adversarial inputs so the property test exercises both accept and reject paths.

### Boundary values — `st.integers`, `st.floats`

```python
boundary_ints = st.integers(min_value=-(2**31), max_value=2**32 + 1)

length_fields = st.integers(min_value=-1, max_value=2**16 + 1)

dangerous_floats = st.floats(
    allow_nan=True, allow_infinity=True, allow_subnormal=True
)
```

Integer overflows, underflows, signed/unsigned confusion, and length-field mismatches. `st.floats` with NaN/Inf/subnormal catches comparison bugs and serialization edge cases.

### Nested structures — `st.lists`, `st.dictionaries`, `st.recursive`

```python
nested_json = st.recursive(
    st.one_of(st.none(), st.booleans(), st.integers(), st.text(max_size=32)),
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=16), children, max_size=5),
    ),
    max_leaves=50,
)

deep_nesting = st.recursive(
    st.just("leaf"),
    lambda children: st.lists(children, min_size=1, max_size=2),
    max_leaves=100,
)
```

`st.recursive` builds arbitrarily nested structures — use it to find parser depth-limit bugs, stack overflows in recursive descent parsers, and quadratic-blowup in serializers. `max_leaves` caps total complexity. `st.dictionaries` and `st.lists` with bounded sizes for flat collection abuse (duplicate keys, empty collections, single-element edge cases).

### Edge constants — `st.just`, `st.none`, `st.nothing`

`st.just(x)` always returns `x` — use it to pin one field while varying others. `st.none()` generates `None` — use it to test null-handling paths. `st.nothing()` produces no values — use it to disable a branch in `st.one_of` during debugging.

## Differential Testing

The highest-value security application: compare two implementations on the same generated input and assert they agree on security-relevant fields.

### URL parser differential

```python
from hypothesis import given, settings, example
from hypothesis import strategies as st
from urllib.parse import urlparse

@settings(max_examples=500, deadline=1000)
@example("http://evil.com%00@good.com/path")
@example("http://good.com@evil.com/")
@example("http://127.0.0.1:80@evil.com/")
@given(st.from_regex(r"https?://[a-z0-9.@:%]{1,64}/[a-z0-9/.]{0,32}", fullmatch=True))
def test_url_host_agreement(url: str) -> None:
    stdlib_host = urlparse(url).hostname
    app_host = app_url_parser(url).hostname  # the target under test
    assert stdlib_host == app_host, (
        f"Host disagreement: stdlib={stdlib_host}, app={app_host} for {url!r}"
    )
```

The `@example` seeds inject known SSRF bypass patterns — `%00` truncation, `@` authority confusion, port-embedded `@`. Hypothesis discovers novel variants via the `st.from_regex` strategy.

### Encoding/canonicalization differential

```python
@settings(max_examples=300, deadline=500)
@given(st.text(
    alphabet=st.characters(categories=("L", "N"), include_characters="/<>%+. "),
    max_size=128,
))
def test_canonicalization_preserves_origin(raw: str) -> None:
    normalized = path_canonicalize(raw)
    assert not normalized.startswith("/../"), f"Traversal escape: {raw!r} → {normalized!r}"
    assert "\x00" not in normalized, f"Null byte survived: {raw!r}"
    if path_allowlist_check(raw):
        assert path_allowlist_check(normalized), (
            f"Allowlist bypass: {raw!r} accepted, canonicalized {normalized!r} rejected"
        )
```

### Validator vs consumer agreement

```python
@settings(max_examples=250, deadline=500)
@given(st.binary(max_size=1024))
def test_validator_consumer_agreement(payload: bytes) -> None:
    validator_result = input_validator(payload)
    if validator_result.accepted:
        consumed = consumer_process(payload)
        assert consumed.content_type == validator_result.declared_type, (
            f"Type disagreement: validator says {validator_result.declared_type}, "
            f"consumer says {consumed.content_type} for {payload[:64]!r}"
        )
```

The pattern: if the security gate accepts, the downstream consumer must interpret the input the same way. A disagreement is the vulnerability.

## Property-Based Fuzzing

When there is no second implementation to diff against, test invariants of a single function.

### Round-trip properties

```python
@given(st.dictionaries(st.text(max_size=16), st.text(max_size=64), max_size=10))
def test_serialize_roundtrip(data: dict) -> None:
    serialized = custom_serialize(data)
    deserialized = custom_deserialize(serialized)
    assert deserialized == data
```

Failures mean data loss or data injection during the round trip. In security context: can the serialization introduce a delimiter, escape sequence, or new field that the deserializer interprets differently?

### No-new-delimiter property

```python
DELIMITERS = set(";&|`$(){}[]<>\n\r\x00")

@given(st.text(max_size=128))
def test_encode_no_new_delimiters(raw: str) -> None:
    original_delims = DELIMITERS & set(raw)
    encoded = custom_encode(raw)
    new_delims = (DELIMITERS & set(encoded)) - original_delims
    assert not new_delims, f"Encoding introduced delimiters: {new_delims} from {raw!r}"
```

### Idempotency

```python
@given(st.text(max_size=256))
def test_normalize_idempotent(raw: str) -> None:
    once = normalize(raw)
    twice = normalize(once)
    assert once == twice, f"Non-idempotent: {raw!r} → {once!r} → {twice!r}"
```

Non-idempotent normalization means the output changes meaning on re-processing — a double-encoding or double-decoding vulnerability.

## Stateful Testing

`RuleBasedStateMachine` models multi-step interactions where the system's state gates what operations are valid. Use it for authentication flows, session management, and authorization boundaries.

```python
from hypothesis.stateful import RuleBasedStateMachine, rule, initialize, Bundle

class AuthStateMachine(RuleBasedStateMachine):
    tokens = Bundle("tokens")

    @initialize()
    def setup(self):
        self.server = create_test_server()
        self.authenticated = False
        self.role = None

    @rule(target=tokens)
    def login_as_user(self):
        token = self.server.login("testuser", "testpass")
        self.authenticated = True
        self.role = "user"
        return token

    @rule(token=tokens)
    def access_admin_endpoint(self, token):
        result = self.server.request("/admin/users", token=token)
        if self.role != "admin":
            assert result.status_code == 403, (
                f"Non-admin accessed admin endpoint: role={self.role}, status={result.status_code}"
            )

    @rule(token=tokens)
    def logout(self, token):
        self.server.logout(token)
        self.authenticated = False

    @rule(token=tokens)
    def use_after_logout(self, token):
        if not self.authenticated:
            result = self.server.request("/api/data", token=token)
            assert result.status_code == 401, (
                f"Token valid after logout: status={result.status_code}"
            )
```

Hypothesis explores rule sequences: login → admin access, login → logout → use-after-logout, repeated logins. The `Bundle` passes outputs (tokens) between rules. Shrinking reduces a failing sequence to the minimal steps that reproduce the bug.

Key stateful patterns for security:
- **Skip-step attacks:** Does accessing a protected endpoint without prior login succeed?
- **Token reuse after invalidation:** Does a session token work after logout/expiry?
- **Role escalation across state transitions:** Does switching from user to admin context leak permissions?
- **Concurrent session interference:** Does one session's state affect another's authorization? (Model two sessions in the state machine.)

## Example Shrinking

When a property test fails, Hypothesis automatically shrinks the counterexample to the minimal input that still fails. For security research this is the difference between "this 847-byte input crashes the parser" and "this 3-byte input crashes the parser" — the minimal example reveals the root cause.

Shrinking is Hypothesis's default behavior; no configuration needed. The shrunk example appears in the test output and can be pinned with `@example(...)` as a regression test.

When a shrunk example is surprising (shorter or structurally different from what you expected), it often reveals a simpler attack path. Examine the shrunk form before the original.

## Settings and Resource Controls

```python
from hypothesis import settings, HealthCheck

@settings(
    max_examples=500,         # inputs per test run (default 100; raise for security research)
    deadline=2000,            # ms per example (raise for complex parsers; None disables)
    stateful_step_count=50,   # steps per stateful run
    suppress_health_check=[
        HealthCheck.too_slow,       # suppress only when slow is expected and bounded
        HealthCheck.filter_too_much, # suppress when tight strategy filtering is intentional
    ],
    database=None,            # disable the example database for ephemeral sandbox runs
    derandomize=True,         # reproducible runs (same examples every time)
)
def test_property(raw):
    ...
```

Key settings for security research:

- `max_examples`: 100 is the default. Raise to 500–2000 for security-critical properties. Diminishing returns above 5000 — if 2000 examples don't find a bug, the property likely holds or the strategy distribution is wrong.
- `deadline`: milliseconds per individual example. Set to `None` only when you know the function can be slow and you've bounded the input size. A function that hangs on specific inputs is a finding — don't suppress it globally.
- `derandomize=True`: makes runs reproducible by seeding from the test function's name. Use for CI and for sharing results across researchers.
- `database`: Hypothesis caches failing examples to a local SQLite database and replays them first. In the sandbox, set `database=None` if the container is ephemeral; keep it for multi-session engagements.
- `stateful_step_count`: maximum rule invocations per stateful test run. 50 is adequate for most auth/session models; raise for complex state machines.
- `suppress_health_check`: suppress selectively, not globally. Each suppressed check is a finding channel you're closing.

## Reproducibility

- Keep the minimized failing example as a pinned `@example(...)` regression test — this survives strategy changes.
- Record the hypothesis version (`6.168.5`), Python version (`3.14.7`), and the exact library versions of the parsers under test.
- For cross-session replay, keep Hypothesis's example database in a task-specific directory (`database=DirectoryBasedExampleDatabase("/path/to/db")`).
- In the sandbox, the database path must be within the container's writable filesystem — use the working directory or `/tmp`.
- Classify nondeterminism before suppressing health checks. Timing, global state, environment, and shared caches can create flaky false differentials.
- `derandomize=True` makes a test fully reproducible without the database — the examples are derived from the test name alone.

## Safety and Resource Controls

- Adapt target functions so tests cannot reach the network or execute commands. Hypothesis generates inputs fast — an unrestricted generator hitting a live endpoint is a DoS.
- Use temporary directories and non-secret corpora for parsers that require files.
- Put native parsers in a disposable, networkless process with CPU, memory, file-size, and process ceilings.
- Do not disable deadlines globally to hide hangs; isolate and bound intentionally slow examples.
- A crash, timeout, or excessive allocation is a robustness result. Prove a security boundary or exploitability separately.
- Never reuse captured credentials, customer content, or production requests as generative corpora without sanitization.
- Bound all strategies: `max_size` on text/binary/lists, `max_leaves` on recursive, `max_examples` on settings. Unbounded strategies exhaust memory and produce uninterpretable failures.

## Chaining to Vulnerability Classes

Hypothesis is the local-code testing harness for several vulnerability classes in the corpus. Route to these playbooks for the attack patterns and invariants specific to each:

- `vulnerabilities/semantic_confusion.md` — parser differentials are the core Hypothesis use case. Generate inputs that two parsers interpret differently; the semantic confusion file maps the differential patterns that lead to exploitable confusion (URL authority, content-type, encoding negotiation).
- `vulnerabilities/sql_injection.md`, `vulnerabilities/nosql_injection.md`, `vulnerabilities/header_injection.md` — test that input sanitization and parameterization agree on what constitutes a delimiter, escape, or command boundary. Hypothesis finds the encoding/normalization edge cases that bypass filters.
- `vulnerabilities/insecure_deserialization.md` — round-trip property testing catches gadget injection: `deserialize(serialize(obj))` should not instantiate unexpected types or invoke unexpected methods.
- `vulnerabilities/authentication_jwt.md` — `st.composite` JWT payloads with algorithm confusion (`none`, `HS256` vs `RS256`), claim manipulation, and expiry boundary testing.
- `vulnerabilities/race_conditions.md` — stateful testing models concurrent state transitions. The `RuleBasedStateMachine` finds sequences where interleaved operations violate authorization invariants.
- `vulnerabilities/prototype_pollution.md` — `st.dictionaries` with `__proto__`, `constructor`, and `prototype` keys to test that object merge/assignment functions reject or sanitize prototype-polluting paths.
- `vulnerabilities/path_traversal_lfi_rfi.md` — no-traversal-escape property testing with `st.from_regex` generating path segments with dot-segments, backslashes, null bytes, and encoding variants.
- `vulnerabilities/ssrf.md` — URL parser differential testing: generate URLs that one parser resolves to an internal host and another resolves to the allowlisted host.

## Validation Deliverable

1. Stated invariant and why it protects a security boundary
2. Adapters and exact component/version pair compared
3. Bounded strategies and resource settings
4. Minimized counterexample and both interpretations
5. Stable explicit `@example(...)` regression test
6. Impact trace from disagreement to privileged consumer
7. Fixed-version or corrected-invariant result
