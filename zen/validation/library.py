# ZEN-EVAL-QUARANTINE: do-not-feed-to-agent
"""The deterministic validator library — replays evidence, runs an oracle — quarantined.

"Confirmed" must mean *validated outside the model*. The validator library makes
it so: given a candidate finding and the re-executable :class:`~zen.tools.ledger.objects.Evidence`
behind it, it **replays that evidence in non-model code** through an injected
:class:`Replayer`, then runs the declared oracle over what the replay observed. The
verdict it returns is the only thing that may carry a finding to ``confirmed``.

The load-bearing distinction — the one a trace/signature match cannot make — is
decided here: a replay that *reached the surface* but produced **no** oracle signal
yields a verdict with ``passed=False`` and ``reach_only=True`` (rejected), while a
replay whose observation yields the oracle signal yields ``passed=True`` carrying
the captured signal (confirmed). "Reached the tier" and "performed the exploit and
observed its effect" are therefore different verdicts, grounded in the presence or
absence of the re-observed oracle signal.

An LLM judge is permitted only as a **pre-filter** in front of this: it may reject
a candidate early (downgrade-only), but it can never confirm one — the
deterministic oracle is always the final gate.

This file is quarantined (marker above; :mod:`zen.validation.quarantine`): it runs
the answer key, so neither the agent nor the optimizer may read it.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol

from zen.tools.ledger.objects import ValidatorVerdict
from zen.validation.oracles import DETERMINISTIC_ORACLES, ReplayObservation


if TYPE_CHECKING:
    from collections.abc import Callable

    from zen.tools.ledger.objects import Evidence, Finding, OracleShape


class Replayer(Protocol):
    """Re-executes a piece of evidence in non-model code and reports what it saw.

    The runtime supplies a concrete replayer per medium (an HTTP replayer that
    re-sends the captured exchange, a command replayer that re-runs the argv, a
    browser replayer that re-drives the interaction). The library depends only on
    this shape, so it is deterministic and testable with a stub.
    """

    def replay(self, evidence: Evidence) -> ReplayObservation:
        """Re-execute ``evidence`` and return what the re-execution observed."""
        ...


@dataclass(frozen=True)
class OracleExpectation:
    """What the oracle should observe on re-execution for this finding.

    ``shape`` selects the oracle; ``value`` is the concrete thing to observe — the
    planted canary, the expected effect token, the predicted differential marker,
    or the crash signature. Both are supplied by the party that knows the ground
    truth (the engagement setup or the harness), never by the agent.
    """

    shape: OracleShape
    value: str


class ValidatorLibrary:
    """Produces execution verdicts by replaying evidence and running oracles."""

    def __init__(
        self,
        replayer: Replayer,
        *,
        prefilter: Callable[[Finding, Evidence], bool] | None = None,
    ) -> None:
        self._replayer = replayer
        # Optional LLM-judge pre-filter. It may only REJECT (return False) before
        # the oracle runs; it is never consulted to confirm. The deterministic
        # oracle is the final gate.
        self._prefilter = prefilter

    def validate(
        self,
        finding: Finding,
        evidence: Evidence,
        expectation: OracleExpectation,
        *,
        author: str,
        verdict_id: str | None = None,
    ) -> ValidatorVerdict:
        """Replay ``evidence`` and return the execution verdict for ``finding``."""
        vid = verdict_id or f"vd-{uuid.uuid4().hex[:12]}"

        if self._prefilter is not None and not self._prefilter(finding, evidence):
            # Pre-filter rejection: a downgrade, never a confirmation. Not
            # reach-only — the candidate was dismissed before any replay.
            return self._reject(
                vid, finding, expectation, author,
                reach_only=False,
                detail="rejected by the LLM pre-filter before re-execution",
                evidence_id=evidence.id,
            )

        observation = self._replay(evidence)
        if not observation.reached:
            return self._reject(
                vid, finding, expectation, author,
                reach_only=False,
                detail="re-execution did not reach the surface; no verdict possible",
                evidence_id=evidence.id,
            )

        oracle = DETERMINISTIC_ORACLES.get(expectation.shape)
        if oracle is None:
            return self._reject(
                vid, finding, expectation, author,
                reach_only=False,
                detail=(
                    f"no deterministic oracle for shape {expectation.shape!r}; "
                    "route this class to the clean-context reviewer"
                ),
                evidence_id=evidence.id,
            )

        signal = oracle(observation, expectation.value)
        if signal.present:
            return ValidatorVerdict(
                id=vid,
                finding_id=finding.id,
                oracle=expectation.shape,
                passed=True,
                reach_only=False,
                author=author,
                oracle_signal=signal.captured,
                replayed_evidence_ids=[evidence.id],
                detail=f"CONFIRMED: {signal.detail}",
            )
        # Reached the surface, re-executed, but no oracle signal: the exploit was
        # not performed. This is the distinction a signature oracle cannot draw.
        return self._reject(
            vid, finding, expectation, author,
            reach_only=True,
            detail=(
                f"REACH-ONLY: {signal.detail}. The evidence reached the surface but the "
                "re-executed exploit produced no oracle signal, so the finding is not confirmed."
            ),
            evidence_id=evidence.id,
        )

    def _replay(self, evidence: Evidence) -> ReplayObservation:
        try:
            return self._replayer.replay(evidence)
        except Exception:  # noqa: BLE001 - a replay that errors did not reach the surface
            return ReplayObservation(reached=False)

    @staticmethod
    def _reject(
        vid: str,
        finding: Finding,
        expectation: OracleExpectation,
        author: str,
        *,
        reach_only: bool,
        detail: str,
        evidence_id: str,
    ) -> ValidatorVerdict:
        return ValidatorVerdict(
            id=vid,
            finding_id=finding.id,
            oracle=expectation.shape,
            passed=False,
            reach_only=reach_only,
            author=author,
            oracle_signal={},
            replayed_evidence_ids=[evidence_id],
            detail=detail,
        )


__all__ = ["OracleExpectation", "Replayer", "ValidatorLibrary"]
