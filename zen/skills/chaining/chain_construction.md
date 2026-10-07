---
name: chain-construction
description: The precondition/postcondition attack-graph model for building multi-hop exploit chains — nodes, edges, capability transfer, and end-to-end path construction.
---

# Chain Construction

A chain is a sequence of primitives where each hop's postcondition
satisfies the next hop's precondition on the actual target. The model
is a directed graph: nodes are vulnerability primitives with typed
preconditions and postconditions; edges exist when a predecessor's
postcondition genuinely provides a successor's precondition. A chain
is real when every edge is demonstrated, not when the graph *could*
connect.

This skill owns the construction framework — the graph model, node
and edge definitions, path-building discipline, and the structural
rules that separate a demonstrated chain from an asserted one. The
per-class grant/require pairs that populate the graph live in
`chaining/primitive_taxonomy`. How to prove each edge is real lives
in `chaining/chain_validation`. How to score the completed chain
lives in `chaining/chain_severity`.

## The Graph Model

### Nodes

A node is a vulnerability primitive — one exploitable instance of a
vulnerability class on a specific target. Every node carries:

- **Precondition**: the capability the attacker must already hold
  before this primitive is exploitable. Stated as a concrete
  capability, not as a vulnerability class name. Examples:
  "authenticated session with role ≥ user", "reachable HTTP
  parameter on the target", "local file write to a path the
  template engine scans."

- **Postcondition (grant)**: the capability the attacker gains by
  exploiting this primitive. Stated the same way. Examples:
  "attacker-chosen outbound HTTP request from the server's network
  position", "arbitrary SQL execution against the application
  database", "cross-object read of any user's record via swapped
  identifier."

- **Controllables**: the subset of the granted capability the attacker
  actually controls. An SSRF that permits only `GET` on `https://`
  with no custom headers is a different node from an SSRF that permits
  arbitrary method, scheme, and headers — even on the same endpoint.
  The controllables set is part of the node definition.

- **Position**: where in the target's architecture this primitive
  executes. A background worker, a frontend proxy, a CI runner, and
  the main application server occupy different network positions with
  different egress rules, different credential access, and different
  metadata reachability. Position is part of the node because it
  constrains what the postcondition can actually reach.

### Edges

An edge connects node A to node B when A's postcondition provides B's
precondition. The edge carries:

- **Capability transferred**: the specific capability that flows from
  A to B. State this explicitly — "A grants server-side file read;
  B requires a readable path containing a signing key; the key is at
  `/app/config/secret_key` which A can reach." This sentence is the
  edge's existence proof.

- **Transfer fidelity**: whether the transferred capability is
  exact or degraded. An SSRF that reaches an internal endpoint but
  strips custom headers degrades the capability — the downstream
  node that requires headers (IMDSv2) cannot chain through it. A
  file read that returns base64-encoded content degrades
  differently from one that returns raw bytes.

- **Reachability on this target**: the edge exists in the abstract
  graph (SSRF *can* reach metadata endpoints) but may not exist on
  this target (egress firewall blocks `169.254.169.254`, or IMDSv2
  hop-limit is 1 and the container is two hops away). An edge is
  real only after reachability is confirmed.

### Paths

A path is an ordered sequence of edges from an entry node to a
terminal node. The entry node's precondition is the attacker's
starting position (typically "unauthenticated internet access" or
"authenticated low-privilege session"). The terminal node's
postcondition is the chain's end-state capability — this is what
the chain achieves and what severity is scored against.

## Building a Chain

### Step 1 — Enumerate primitives

Collect every confirmed or high-confidence primitive on the target.
Each becomes a node. For each node, state its precondition,
postcondition, controllables, and position using the vocabulary from
`chaining/primitive_taxonomy`. Do not speculate primitives — only
confirmed findings and high-confidence candidates enter the graph.

### Step 2 — Map edges

For every pair of nodes (A, B), ask: does A's postcondition satisfy
B's precondition on this target? Three outcomes:

- **Yes, demonstrated**: A's output was used as B's input and B
  fired. The edge is confirmed.
- **Yes, reachable but not yet demonstrated**: A's postcondition
  matches B's precondition in kind, and reachability has been
  confirmed (A can reach the endpoint/file/service B needs), but
  the full A→B transfer has not been executed end-to-end. The edge
  is plausible.
- **No**: A's postcondition does not provide what B needs, or
  reachability is blocked. No edge.

### Step 3 — Find paths

Traverse the graph from every entry-reachable node to every
high-value terminal postcondition. Prioritize paths by:

1. Terminal capability value (RCE > credential extraction > data
   read > information disclosure).
2. Path length — shorter paths have fewer assumptions.
3. Edge confidence — paths with all-demonstrated edges outrank paths
   with plausible edges.

### Step 4 — Walk the path end-to-end

Execute (or trace, in white-box) the full path from entry to
terminal. At each hop, confirm:

- The predecessor's postcondition is actually available (not
  consumed, not timed out, not rate-limited away).
- The successor's precondition is actually satisfied by what the
  predecessor produced (not just by what it *could* produce in
  theory).
- The capability transfer is faithful — the data/credential/access
  that flows across the edge is intact and usable.

A chain where any hop's transfer is unconfirmed is an asserted
chain, not a demonstrated one. Report it with the gap named.

## Structural Rules

### One-way capability flow

Capabilities flow forward through the chain. A later hop does not
retroactively validate an earlier one. If hop 3 fails, hops 1–2
are still real findings — but the chain stops at hop 2's
postcondition.

### Branching and convergence

A single node's postcondition may satisfy multiple successors'
preconditions — the graph branches. Conversely, a node may require
preconditions from two predecessors — the graph converges. Both are
common:

- **Branch**: SSRF grants internal reachability. That reachability
  satisfies the precondition for metadata-endpoint probing *and*
  the precondition for internal-API access *and* the precondition
  for Docker-socket reach. Three parallel edges from one node.

- **Convergence**: RCE via deserialization requires (a) a reachable
  deserialization sink *and* (b) a known gadget chain on the
  classpath. (a) comes from SSRF reaching an internal RMI endpoint;
  (b) comes from information disclosure revealing the dependency
  manifest. Two predecessors, one successor.

### Dead ends and partial chains

A chain that reaches an intermediate postcondition but not a
high-impact terminal is still a finding — the intermediate
capability is real. Report the demonstrated chain with its actual
terminal postcondition, not the hypothetical terminal you hoped
to reach.

### Capability consumption

Some primitives are single-use: a race condition that mints a
duplicate token consumes the race window; a CSRF that changes a
password invalidates the session the chain was using. Model
consumption as a postcondition constraint: "grants X, but
consumes Y." The downstream hop must not depend on Y.

### Environment-dependent edges

An edge that exists in one deployment may not exist in another.
Cloud-metadata reachability depends on the provider and the
instance configuration. Internal-service reachability depends on
network segmentation. State every environment assumption on the
edge.

## Routing Convention

Every hop in a chain routes to the skill file that owns the
primitive. State the filename at each arrow:

```
SSRF (ssrf.md) → internal Docker API reach
  → container create with host mount (rce.md) → host filesystem
  → credential read (path_traversal_lfi_rfi.md) → cloud key
  → cloud pivot (cloud/aws.md)
```

The routing convention makes the chain auditable: a reviewer can
open each referenced file and confirm the primitive is real per
that file's confirmation methodology.

## Chain vs. Single Finding

A chain is warranted when:

- The terminal capability is higher-impact than any individual
  node's postcondition.
- Each hop is demonstrated or high-confidence with a named gap.
- The chain adds reachability or privilege that no single finding
  provides.

A chain is *not* warranted when:

- A single finding already achieves the terminal capability (e.g.,
  unauthenticated RCE does not need a chain — it is one node).
- The "chain" is padding: stringing low-value findings together
  does not make them high-value unless the terminal capability is
  genuinely high-impact and genuinely unreachable without the chain.
- The edges are speculative ("could combine with") rather than
  demonstrated or reachability-confirmed.

## Anti-Patterns

**Asserted chains.** "SSRF + IDOR could lead to RCE" without
demonstrating that the SSRF reaches the IDOR endpoint, that the
IDOR produces a capability the RCE primitive needs, and that the
RCE primitive is present. Every "could" is an unconfirmed edge.

**Severity inflation.** Chaining three medium findings does not
produce a critical finding unless the terminal postcondition is
genuinely critical-tier. The chain's severity is its demonstrated
end-state, not the sum of its parts.

**Hypothetical nodes.** Including a primitive the target might have
("if there were a deserialization sink here") to extend a chain.
Every node must be confirmed or high-confidence on this target.

**Ignoring controllables.** Connecting an SSRF to a downstream that
requires headers when the SSRF's controllables do not include
headers. The edge does not exist — the controllables gate it.

**Duplicate-reporting the chain and its parts.** Each node in a
demonstrated chain is also a standalone finding. Report both: the
individual findings at their own severity, and the chain at the
chain's demonstrated terminal severity. Do not double-count the
impact.
