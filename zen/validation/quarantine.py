"""The validator quarantine boundary, as importable data + a checker.

Section 2.2's confirmation machinery — the deterministic oracles, the validator
library that runs them, the clean-context reviewer, and the per-run ground truth
they rest on — is an *answer key*. If the agent could read it, it could fabricate
evidence that contains exactly the signal an oracle looks for; if the 2.2
self-evolution optimizer could read or edit it, it could learn or weaken the
confirmation function. Either collapses "confirmed" back into something gameable.

So this module states, once and in code, that the validator's oracle/ground-truth
boundary is off-limits — mirroring the eval harness's own quarantine
(:mod:`evals.quarantine`) rather than re-deriving the policy from prose. A test
(:mod:`tests.test_validator_quarantine`) asserts the boundary holds:

1. every quarantined file carries the greppable :data:`NO_READ_MARKER`;
2. the validator package is not on any agent discovery path (it is under
   ``zen/validation/``, never ``zen/skills/``, and contributes no tool);
3. the optimizer's no-read list covers these paths.

This module itself is *not* quarantined — it is the public declaration of the
boundary, carrying no oracle logic and no ground truth. It is class-agnostic: it
names files, never a vulnerability class.
"""

from __future__ import annotations

from pathlib import Path


#: One greppable marker, shared verbatim with the eval harness so a single token
#: marks every answer-key path the agent and the optimizer must not ingest. It is
#: a string literal here (not imported from evals) because the quarantine rule is
#: itself that no ``zen`` module imports ``evals``.
NO_READ_MARKER = "ZEN-EVAL-QUARANTINE: do-not-feed-to-agent"

#: Paths (relative to the repository root) that hold the validator's oracle logic
#: and the per-run ground truth it depends on. The 2.2 optimizer, and any tooling
#: that assembles agent-facing context, MUST NOT read, ingest, embed, or edit
#: these. The validator library runs them; nothing feeds their source to a model.
VALIDATOR_NO_READ: tuple[str, ...] = (
    "zen/validation/oracles.py",
    "zen/validation/library.py",
    "zen/validation/reviewer.py",
    "zen/validation/ground_truth.py",
)


def quarantined_paths() -> tuple[Path, ...]:
    """The quarantined files as absolute paths under the repository."""
    repo_root = Path(__file__).resolve().parents[2]
    return tuple(repo_root / rel for rel in VALIDATOR_NO_READ)


def asserts_outside_optimizer_reach() -> list[str]:
    """Human-readable invariants the quarantine test enforces, for error text."""
    return [
        f"every validator oracle/ground-truth file is annotated {NO_READ_MARKER!r}",
        "the validator package is under zen/validation/, not a skill search directory",
        "the validator package contributes no agent tool",
        "the optimizer no-read list covers every VALIDATOR_NO_READ path",
    ]


__all__ = [
    "NO_READ_MARKER",
    "VALIDATOR_NO_READ",
    "asserts_outside_optimizer_reach",
    "quarantined_paths",
]
