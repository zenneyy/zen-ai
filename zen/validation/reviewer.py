# ZEN-EVAL-QUARANTINE: do-not-feed-to-agent
"""The clean-context reviewer — re-observes a differential itself — quarantined.

Some class families resist a mechanical oracle: authorization and business logic
have no planted canary or crash to read back, only *behavior that differs by who
is asking or what state they are in*. For those, confirmation is a judgement — but
a judgement that must rest on behavior the reviewer **re-observes for itself**, not
on the hunter's story.

So the reviewer is given a deliberately **clean context**: the re-executable
evidence, the target, and a differential *probe* (which principals to compare over
which resource) — and **not** the hunter's narrative, hypothesis, or reasoning.
There is no field on :class:`ReviewInput` to carry that narrative, so the reviewer
cannot be led by it. It re-runs the probe over the principals itself and grounds
its verdict in the role-/tenant-/state-differential it observes: if the
principal-under-test reaches a resource marker that only the control principal
should, that is an authorization regression it has confirmed first-hand.

This is the non-deterministic counterpart to :mod:`zen.validation.library`; it
produces the same :class:`~zen.tools.ledger.objects.ValidatorVerdict`, so a
reviewer sign-off carries a finding to ``confirmed`` through the same ledger gate.

This file is quarantined (marker above; :mod:`zen.validation.quarantine`).
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from zen.tools.ledger.objects import ValidatorVerdict
from zen.validation.oracles import ReplayObservation


if TYPE_CHECKING:
    from zen.tools.ledger.objects import Evidence


@dataclass(frozen=True)
class DifferentialProbe:
    """How to re-observe a role-/tenant-/state-differential, with no claim attached.

    The probe says *what to compare*, not *what the answer is*: run the finding's
    evidence as ``principal_under_test`` and as ``control_principal``, and watch
    for ``resource_marker`` — a value only the control principal is entitled to
    see. A regression is the marker turning up for the principal-under-test.
    """

    principal_under_test: str
    """The principal that should NOT reach the resource (the attacker role/tenant)."""

    control_principal: str
    """The principal that legitimately owns the resource (the baseline)."""

    resource_marker: str
    """A value present only in the control principal's resource — re-observed, not
    asserted. Its appearance for the principal-under-test is the differential."""


@dataclass(frozen=True)
class ReviewInput:
    """Everything the reviewer is given — and, by omission, what it is NOT given.

    It carries the re-executable evidence, the target, and the differential probe.
    It carries **no** hunter narrative, hypothesis text, or author reasoning: there
    is no field for it, so the reviewer's verdict cannot rest on the story it was
    told, only on what it re-observes.
    """

    finding_id: str
    evidence: Evidence
    target: str
    probe: DifferentialProbe


class PrincipalReplayer(Protocol):
    """Re-executes evidence *as a named principal*, for differential review.

    The runtime supplies a replayer that can authenticate as each principal (a
    role, a tenant, a session) and re-send the captured interaction as them, so
    the reviewer can compare what each is actually allowed to reach.
    """

    def replay_as(self, evidence: Evidence, principal: str) -> ReplayObservation:
        """Re-execute ``evidence`` authenticated as ``principal``."""
        ...


class CleanContextReviewer:
    """Confirms authorization/business-logic findings by re-observing a differential."""

    def __init__(self, replayer: PrincipalReplayer) -> None:
        self._replayer = replayer

    def review(self, review_input: ReviewInput, *, author: str) -> ValidatorVerdict:
        """Re-observe the probe and return a verdict grounded in the differential.

        The verdict passes only when the control principal reaches the resource
        marker (the baseline holds, so the marker is real) **and** the
        principal-under-test also reaches it (the regression). A marker the control
        principal cannot reach proves nothing about isolation and is not a pass; a
        marker the principal-under-test cannot reach is correct isolation, not a
        finding.
        """
        vid = f"vd-{uuid.uuid4().hex[:12]}"
        probe = review_input.probe
        control = self._replay_as(review_input.evidence, probe.control_principal)
        under_test = self._replay_as(review_input.evidence, probe.principal_under_test)

        baseline_holds = probe.resource_marker in control.response_text
        crossed = probe.resource_marker in under_test.response_text

        if baseline_holds and crossed:
            return ValidatorVerdict(
                id=vid,
                finding_id=review_input.finding_id,
                oracle="reviewer_differential",
                passed=True,
                reach_only=False,
                author=author,
                oracle_signal={
                    "differential": (
                        f"{probe.principal_under_test} reached a resource scoped to "
                        f"{probe.control_principal}"
                    ),
                },
                replayed_evidence_ids=[review_input.evidence.id],
                detail=(
                    "CONFIRMED: re-observed the principal-under-test reaching a resource the "
                    "control principal scopes — a role/tenant isolation regression, grounded "
                    "in the reviewer's own re-execution, not the hunter's narrative."
                ),
            )

        if not baseline_holds:
            detail = (
                "INCONCLUSIVE: the control principal did not reach the resource marker on "
                "re-execution, so the probe's baseline does not hold; no isolation claim can "
                "be grounded."
            )
        else:
            detail = (
                "REJECTED: the principal-under-test did not reach the control's resource on "
                "re-execution — isolation held, so there is no regression to confirm."
            )
        return ValidatorVerdict(
            id=vid,
            finding_id=review_input.finding_id,
            oracle="reviewer_differential",
            passed=False,
            reach_only=not baseline_holds,
            author=author,
            oracle_signal={},
            replayed_evidence_ids=[review_input.evidence.id],
            detail=detail,
        )

    def _replay_as(self, evidence: Evidence, principal: str) -> ReplayObservation:
        try:
            return self._replayer.replay_as(evidence, principal)
        except Exception:  # noqa: BLE001 - a failed replay observes nothing
            return ReplayObservation(reached=False)


__all__ = ["CleanContextReviewer", "DifferentialProbe", "PrincipalReplayer", "ReviewInput"]
