---
name: blind-revalidation
description: Fresh-session re-test discipline — re-validate a finding without priming, confirmation-bias controls, and the skeptical-second-reviewer standard.
---

# Blind Revalidation

Confirmation bias is the most persistent failure mode in security
testing. Once you believe a finding is real, every ambiguous signal
confirms it. Blind revalidation is the control: re-run the test in
a fresh context where the prior reasoning cannot influence the
result, and ask whether a skeptical second reviewer would reach the
same conclusion from the evidence alone.

This skill owns the re-validation methodology.
`validation/red_team_the_finding` owns the per-class falsification
move; this skill applies *after* the finding has survived
falsification and before it is reported.

## When to Revalidate

- **Every finding rated high or critical.** The cost of a
  false-positive at these severities — lost credibility, wasted
  remediation effort, program distrust — justifies the time.
- **Any finding whose confirmation rested on a single observation.**
  One oracle response, one timing measurement, one callback — single
  observations are inherently noisy.
- **Any finding you are uncertain about** after the falsification
  pass. If you had to argue yourself into believing it, revalidate.
- **Findings that emerged from a long, branching analysis.** The
  longer the reasoning chain that produced the finding, the more
  opportunity for a wrong turn that felt right at the time.

## The Fresh-Session Protocol

### 1. New context, no priming

Open a fresh testing session. Do not re-read the prior analysis
before running the revalidation. The test should succeed or fail on
its own evidence, not on your memory of why it worked last time.

Concrete steps:
- Clear the proxy history. Start a new Burp/mitmproxy/ZAP project.
- Use a fresh OAST domain (new `interactsh-client` invocation).
- Do not copy-paste the prior payload — reconstruct it from the
  finding's claim (the one-sentence statement from
  `red_team_the_finding`).

### 2. Re-derive the payload

From the finding's claim alone, derive the payload independently.
If you cannot re-derive it without consulting the prior analysis,
the finding may rest on a reasoning step that is not in the evidence.

### 3. Execute and observe

Run the test. Record:
- The exact request (full HTTP from proxy capture).
- The exact response (full HTTP from proxy capture).
- The OAST callback or oracle signal (source IP, timing, content).
- The control request (the negative control from
  `validation/negative_control_design`) and its response.

### 4. Compare evidence, not conclusions

Does the fresh evidence match the prior evidence? Compare at the
fact level:
- Same oracle response? Same body difference? Same timing delta?
- Same source IP on the callback?
- Same state change on the follow-up read?

If the fresh evidence matches, the finding is reproducible. If it
does not, investigate the discrepancy before reporting.

## Confirmation-Bias Controls

### The paired-request standard

Every confirmed finding requires at least two requests: the attack
request and the control request. The control request is identical
except for the injected payload — it uses a benign value that
should *not* trigger the vulnerability. The finding is the
*difference* between them.

A finding supported by only the attack request, with no control, is
uncontrolled. The response may be the endpoint's default behavior,
not a reaction to the payload.

### The retry standard

Reproduce the attack-vs-control pair at least three times. A
one-shot success is not confirmation — network jitter, server load,
cache state, and A/B testing all produce one-shot differences.
Record the success rate across retries.

### The scaling standard (for quantitative oracles)

Time-based and boolean-based oracles must *scale* with the injected
parameter:
- `SLEEP(1)` → ~1s delay; `SLEEP(5)` → ~5s delay.
- `AND 1=1` → response A; `AND 1=2` → response B; consistently.

A fixed delay that does not scale with the sleep parameter is not
injection-confirmed — it may be a rate limiter, a slow query, or
network latency.

### The source-IP standard (for OAST oracles)

The callback's source IP must match the target's egress range, not
the tester's machine or browser. Mint a fresh OAST domain per
finding to prevent cross-contamination between tests.

## The Skeptical-Second-Reviewer Standard

Before reporting, ask: would a reviewer who has never seen this
target, given only the evidence package (the request/response
pairs, the OAST callbacks, the state-change confirmations), reach
the same conclusion?

If the answer requires the reviewer to trust your narration ("I
saw the response change" without the captured response), the
evidence package is incomplete.

The evidence package for a passing revalidation:
1. The finding claim (one sentence).
2. The attack request (full HTTP).
3. The attack response (full HTTP).
4. The control request (full HTTP).
5. The control response (full HTTP).
6. The OAST/oracle evidence with source-IP attribution.
7. The retry results (≥3 iterations).
8. The scaling results (for quantitative oracles).

## What Revalidation Failure Means

A finding that fails revalidation is not automatically false — but
it is not confirmed. Possible outcomes:

- **Not reproducible**: the finding worked once but not on retry.
  Downgrade to low-confidence or close as `open_proof_gap`.
- **Reproducible but different**: the revalidation produces a
  signal, but a different one than the original. The original
  analysis may have misidentified the class. Re-classify.
- **Environmental difference**: the target changed between
  original test and revalidation (deployment, config change,
  rate limiter kicked in). Note the dependency and report with
  the environmental constraint.

Cross-reference: `validation/negative_control_design` for the
control-request methodology. `analysis/counterevidence` for
recording closure state.
