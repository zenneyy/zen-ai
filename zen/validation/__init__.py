"""Execution-verdict validation (Phase 2, item 2.2).

"Confirmed" means validated outside the model. This package is the verdict
producer the :class:`~zen.tools.ledger.objects.Finding` constraint requires:

* :class:`~zen.validation.library.ValidatorLibrary` replays a finding's
  re-executable evidence in non-model code and runs a deterministic oracle over
  what the replay observed, returning a verdict that distinguishes "reached the
  surface" from "performed the exploit and observed its effect";
* :class:`~zen.validation.reviewer.CleanContextReviewer` confirms the classes that
  resist a mechanical oracle (authorization, business logic) by re-observing a
  role-/tenant-/state-differential itself, from a clean context that excludes the
  hunter's narrative.

Both produce a :class:`~zen.tools.ledger.objects.ValidatorVerdict`, which the
ledger's :meth:`~zen.tools.ledger.store.ResearchLedger.confirm_finding` requires
(passing and attributable) before a finding may reach ``confirmed``.

The oracle logic and the per-run ground truth it rests on live behind the
quarantine boundary (:mod:`zen.validation.quarantine`): the agent must not read
the answer key, and neither may the 2.2 optimizer.
"""

from __future__ import annotations

from zen.validation.library import OracleExpectation, Replayer, ValidatorLibrary
from zen.validation.quarantine import (
    NO_READ_MARKER,
    VALIDATOR_NO_READ,
    quarantined_paths,
)
from zen.validation.reviewer import (
    CleanContextReviewer,
    DifferentialProbe,
    PrincipalReplayer,
    ReviewInput,
)


def verdict_confirms(verdict: object) -> bool:
    """Whether a verdict is fit to carry a finding to ``confirmed``.

    The ledger enforces the same rule structurally; this is the convenience a
    caller (such as the eval precision grader) uses to count confirmations
    without catching the ledger's rejection exception.
    """
    return bool(
        getattr(verdict, "passed", False)
        and not getattr(verdict, "reach_only", False)
        and str(getattr(verdict, "author", "")).strip()
    )


__all__ = [
    "NO_READ_MARKER",
    "VALIDATOR_NO_READ",
    "CleanContextReviewer",
    "DifferentialProbe",
    "OracleExpectation",
    "PrincipalReplayer",
    "Replayer",
    "ReviewInput",
    "ValidatorLibrary",
    "quarantined_paths",
    "verdict_confirms",
]
