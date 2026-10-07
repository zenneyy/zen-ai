---
name: chain-validation
description: How to prove a multi-hop chain is real, not hypothetical — per-edge demonstration, the demonstrated-vs-asserted distinction, and the reachability evidence each hop requires.
---

# Chain Validation

A chain is real when every edge is demonstrated: each hop's
postcondition genuinely satisfies the next hop's precondition on the
actual target, not in the abstract. This skill owns the validation
methodology — how to prove each edge, what evidence constitutes
proof, and when a chain is demonstrated vs merely asserted.

The graph model and construction discipline live in
`chaining/chain_construction`. The per-class grant/require pairs
live in `chaining/primitive_taxonomy`. Severity scoring of a
validated chain lives in `chaining/chain_severity`.

## The Core Distinction

**Demonstrated chain**: every edge has been executed or traced
end-to-end on the target. The predecessor's output was used as the
successor's input, and the successor fired. The terminal
postcondition was observed.

**Asserted chain**: the edges are plausible — the capability types
match — but the actual transfer has not been confirmed. "SSRF
reaches internal services, and the target runs Redis internally"
is an assertion. "SSRF reached `redis://127.0.0.1:6379`, and the
gopher payload wrote a cron entry that executed" is a demonstration.

**Partial chain**: some edges are demonstrated, others are asserted
or blocked. Report the demonstrated portion at its actual terminal
postcondition, and name the undemonstrated edges as gaps.

Every chain in a report must state which of these three it is.

## Per-Edge Validation

### What constitutes proof of an edge

An edge A→B is proven when:

1. **A's postcondition was produced** — A was exploited and the
   granted capability is observable (a callback arrived, a file was
   read, a credential was extracted, an error confirmed the state
   change).

2. **B's precondition was satisfied by A's output** — the specific
   data, credential, network position, or access that A produced was
   used as B's input. Not "A produces credentials and B needs
   credentials" but "A produced the IAM role credential
   `arn:aws:iam::123:role/app-role`, and B used that credential to
   list S3 buckets."

3. **B fired** — B's exploitation succeeded using the input from A.
   The successor's confirmation methodology (per the owning vuln
   file) was satisfied.

4. **The transfer was faithful** — the capability was not degraded
   below what B requires. If A's file read returned base64-encoded
   content, B must be able to consume base64. If A's SSRF strips
   headers, B must not require headers.

### Evidence per hop type

**Network reachability edges** (SSRF → internal service, RCE →
lateral host):
- OAST callback from the target's egress IP to the internal
  destination, or timing differential confirming connectivity.
- The response from the internal service, distinguishable from
  an error or a proxy's own response.

**Credential extraction edges** (file read → signing key, metadata
→ IAM role):
- The credential itself, or a hash/redacted form that proves
  extraction.
- Successful use of the credential on the downstream service.

**Privilege escalation edges** (IDOR → admin object, BFLA →
privileged action):
- The response differential: the escalated action's result is
  visible (state changed, data returned, role upgraded).
- Confirmation that the starting principal should not have this
  access.

**Code execution edges** (deserialization → RCE, SSTI → shell):
- A safe side-effect that proves execution: a unique file created,
  a DNS callback with an embedded nonce, a `sleep`-proportional
  delay.
- Do not use destructive payloads to prove execution. The smallest
  safe side-effect that confirms the primitive is the standard.

**Data flow edges** (information disclosure → seed for next hop):
- The disclosed data item, and proof it was used as input to the
  next hop (not just that it *could* be used).

## Validation Procedure

For each chain, walk the edges in order:

### 1. Confirm each node independently

Before validating edges, confirm each node is a real finding per its
owning vuln file's confirmation methodology. A chain built on
unconfirmed nodes is doubly speculative.

### 2. Validate edge A→B

Execute A, capture its postcondition output, feed that output into B,
and confirm B fires. Record:

- The exact output from A that constitutes the capability transfer.
- How that output was provided to B (pasted into a parameter,
  used as a header value, saved to a file and referenced).
- B's confirmation signal (per its owning vuln file).

### 3. Validate the full path

After each edge is validated independently, execute the full path
from entry to terminal without interruption. A chain whose edges
each work individually but whose full path fails (because a
credential expires mid-chain, a session is invalidated, or a rate
limiter triggers) is not a demonstrated chain at the full-path
level.

### 4. Record gaps

For each edge that could not be validated:

- State what was attempted.
- State what blocked the validation (egress firewall, missing
  credentials, rate limiting, ethical constraint).
- State what evidence would close the gap.
- Classify the edge as "plausible" (types match, reachability
  unconfirmed) or "speculative" (types may match, no supporting
  evidence).

## Per-Class Validation Moves

The validation move for each edge depends on the vulnerability class
at each end. The owning vuln file's Confirmation section defines
what proves a single finding; the chain-validation question is
whether the *output* of one finding can serve as the *input* to
another.

**SSRF → cloud metadata extraction**: SSRF reaches the metadata IP
(confirmed by OAST or response content). The chain edge is proven
when the metadata *response content* (not just reachability) is
captured and contains the expected credential material. Reachability
alone is not the edge — extraction is.

**File read → credential use**: the file read returns content
(confirmed by matching a known file's expected content). The chain
edge is proven when the extracted credential authenticates against
the target service.

**SQLi → data exfiltration**: SQLi executes arbitrary queries
(confirmed by boolean/time/error/OAST oracle). The chain edge is
proven when the exfiltrated data is meaningful and matches the
claimed impact (user records, credentials, tenant data).

**RCE → lateral movement**: RCE executes commands (confirmed by
safe side-effect). The chain edge is proven when the command's
output reveals a reachable lateral target, and that target is
actually reached.

**IDOR → privilege escalation**: IDOR reads/writes foreign objects
(confirmed by two-account differential). The chain edge is proven
when the foreign object's content or the state change grants a
capability the attacker did not have.

**Information disclosure → seed for exploitation**: disclosure
reveals data (confirmed by response content). The chain edge is
proven when the disclosed data is *used* to exploit the next hop,
not just when it *could* be.

## What Invalidates a Chain

- **A single broken edge** invalidates the full chain. The chain
  truncates at the last demonstrated edge.
- **A consumed capability** that a later hop depends on. If hop 2
  consumes the session that hop 3 needs, the chain is broken at
  hop 3.
- **An environmental assumption that does not hold.** The chain
  assumed IMDSv1 but the target runs IMDSv2 with hop-limit 1.
  The SSRF → metadata edge does not exist on this target.
- **A timing constraint.** The credential extracted in hop 1
  expires before hop 3 executes. The chain is valid only within
  the credential's TTL.

## Reporting a Chain

A validated chain report includes:

1. **The path**: entry node → edge → node → edge → … → terminal
   node, with filenames at each hop.
2. **The evidence per edge**: what was transferred, how it was
   confirmed.
3. **The chain classification**: demonstrated, partial, or
   asserted.
4. **The gaps**: for partial/asserted chains, what edges are
   unconfirmed and what evidence would close them.
5. **The terminal postcondition**: the actual end-state capability,
   not the hoped-for one.
6. **The environment assumptions**: provider, network position,
   configuration dependencies.

## Common Validation Failures

**"Could combine" without transfer evidence.** Two findings on the
same target do not chain unless one's output feeds the other's
input. Proximity is not connectivity.

**Reachability conflated with extraction.** SSRF reaching
`169.254.169.254` is reachability. Reading the IAM credential from
the response is extraction. These are two edges, not one — and the
second may fail (IMDSv2 header gate, hop-limit).

**Safe-probe oracle assumed to prove exec.** A DNS callback from a
deserialization probe proves parser liveness and egress, not code
execution. The exec edge requires its own confirmation (safe
side-effect from the exec payload).

**Single-pass confirmation.** A chain that worked once may not
reproduce. Validate at least twice, or record the single-pass
limitation.
