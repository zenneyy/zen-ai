---
name: chain-severity
description: How to score a multi-hop chain's severity — reachability and enablement framing, per-hop confidence, and the terminal-postcondition rule.
---

# Chain Severity

A chain's severity is its demonstrated terminal postcondition scored
against reachability. Not the sum of its parts, not a compositional
multiplier, not the worst case the graph could theoretically reach.
The severity is: what did the chain actually achieve, and how
reachable is each hop?

This skill owns severity scoring for chains. The graph model lives
in `chaining/chain_construction`. Edge validation lives in
`chaining/chain_validation`. Per-class standalone severity lives in
`analysis/severity_calibration`.

## The Terminal-Postcondition Rule

A chain's impact severity equals the severity of its terminal
postcondition, scored as if that postcondition were a standalone
finding. The chain does not create new impact — it creates
*reachability* to an impact that no single finding achieves alone.

- A chain that terminates in unauthenticated RCE has RCE-level
  impact, regardless of how many hops it took.
- A chain that terminates in reading a low-value config file has
  informational-level impact, even if the intermediate hops
  included SSRF and deserialization.
- A chain that terminates at an intermediate hop (because a later
  edge could not be demonstrated) has the severity of that
  intermediate postcondition.

Score the terminal postcondition using `analysis/severity_calibration`
— the same rubric as standalone findings.

## Reachability Adjustment

The chain's overall severity is the terminal-postcondition impact
*adjusted by* how reachable the full path is. A chain whose every
hop is unauthenticated and internet-reachable has maximum
reachability. A chain that requires an authenticated session, a
specific timing window, a particular deployment configuration, and
a race condition has constrained reachability.

### Reachability factors per hop

For each hop in the chain, assess:

**Authentication required**: does this hop require a session, and
at what privilege level? Unauthenticated hops are more reachable
than authenticated ones. Admin-only hops constrain reachability
significantly.

**Network position**: is the hop reachable from the internet, or
only from an internal network position that a prior hop must
provide? An edge that requires "server-side network position"
depends entirely on the SSRF or RCE that provides it.

**Timing and state constraints**: does the hop require a race
window, a cache state, a deployment phase, a specific
configuration? Each constraint reduces reachability.

**User interaction**: does the hop require a victim to click,
visit, or perform an action? Interaction requirements reduce
reachability proportionally to the plausibility of the
interaction.

### Reachability bands

**Fully reachable**: every hop is unauthenticated, internet-facing,
no timing constraints, no user interaction. The chain is as
exploitable as a direct finding.

**Readily reachable**: requires a common non-privileged role (any
registered user), or one easily met environmental condition. Most
authenticated application chains land here.

**Conditionally reachable**: requires a specific privilege level,
a deployment-specific configuration, a timing window, or moderate
user interaction. The chain works but not against every instance
of the target.

**Narrowly reachable**: requires multiple simultaneous conditions —
a specific role AND a specific config AND a timing window. The
chain is real but the precondition set substantially limits
exploitation.

### Combined severity

The chain's reported severity is the terminal postcondition's
impact band (from `analysis/severity_calibration`) constrained by
the reachability band:

- Terminal postcondition is Critical + Fully reachable → **Critical**.
- Terminal postcondition is Critical + Conditionally reachable →
  **High** (the impact is critical-tier but the reachability
  gates it).
- Terminal postcondition is High + Readily reachable → **High**.
- Terminal postcondition is Medium + Fully reachable → **Medium**
  (reachability does not promote impact — a fully reachable
  medium-impact chain is medium).

Reachability constrains severity downward. It never promotes it
upward. A chain of low-impact findings with perfect reachability
is a low-severity chain.

## Per-Hop Confidence

Each hop's confidence affects the chain's overall confidence.
The chain's confidence is the *minimum* confidence across all
edges, not the average.

- **Demonstrated edge**: the transfer was executed and confirmed.
  High confidence.
- **Plausible edge**: the capability types match and reachability
  was confirmed, but the full transfer was not executed. Medium
  confidence.
- **Speculative edge**: the types might match; no reachability
  evidence. Low confidence.

A chain with one speculative edge is a speculative chain,
regardless of the other edges' confidence.

Report the chain's confidence alongside its severity:
"High-severity chain (demonstrated)" vs "High-severity chain
(partial — edge 3 is plausible, gap: IMDSv2 header gate not
tested)."

## What This Framework Does Not Claim

The severity model is reachability and enablement: what the chain
achieves and how hard it is to exploit. It is not a claim that
chained analysis is inherently more predictive than per-finding
severity. Each hop is a real finding with its own severity; the
chain provides additional context about what an attacker can achieve
by combining them on this target.

## Scoring Procedure

1. **Identify the terminal postcondition.** What is the actual
   end-state capability of the chain? Not the hoped-for one —
   the one where the last demonstrated edge lands.

2. **Score the terminal postcondition's impact** using
   `analysis/severity_calibration`. Apply the same rubric as a
   standalone finding with that capability.

3. **Assess per-hop reachability.** Walk the chain and classify
   each hop's authentication, network, timing, and interaction
   requirements.

4. **Determine the reachability band.** The chain's reachability
   is gated by the most constrained hop.

5. **Combine.** Impact band (from step 2) constrained by
   reachability band (from step 4). Document the reasoning.

6. **State confidence.** The minimum edge confidence across the
   chain.

7. **Report the individual findings too.** Each node is a
   standalone finding at its own severity. The chain is reported
   separately, with the chain severity reflecting the
   demonstrated terminal capability.

## Common Scoring Errors

**Summing severities.** Three medium findings chained do not become
critical. The terminal postcondition decides the impact band.

**Ignoring the most constrained hop.** A chain that requires admin
access at hop 2 is not "fully reachable" because hops 1, 3, and 4
are unauthenticated.

**Scoring the theoretical terminal.** A chain that reached metadata
reachability but not credential extraction terminates at
"metadata endpoint reachable" — score that, not "IAM role
compromised."

**Promoting impact via reachability.** Perfect reachability does
not elevate a medium-impact terminal to high. Reachability only
constrains downward.

**Reporting only the chain and not the parts.** A chain subsumes
its nodes for impact demonstration purposes, but each node is
independently fixable and independently scored. The individual
finding report is the remediation unit; the chain report is the
impact demonstration.
