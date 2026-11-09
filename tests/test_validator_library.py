"""The deterministic validator library (Phase 2, item 2.2).

These prove that "confirmed" means *validated outside the model*: the library
replays a finding's re-executable evidence and runs a deterministic oracle over
what the replay observed, and only an observed oracle signal confirms. The
load-bearing case — mandatory per the Phase-2 review — is that a candidate whose
evidence proves only that a surface was *reached* is rejected, while one whose
re-executed evidence yields the oracle signal is confirmed. The two differ by
exactly one thing: the presence or absence of the re-observed oracle signal.

Everything is class-agnostic: the fixtures describe oracles by their observable
(a canary read back, an effect, a differential, a crash), never a named exploit.
"""

from __future__ import annotations

from dataclasses import dataclass

from zen.tools.ledger import Evidence, EvidenceReplay, Finding, ResearchLedger, VerdictError
from zen.validation import OracleExpectation, ValidatorLibrary, verdict_confirms
from zen.validation.ground_truth import mint_canary
from zen.validation.oracles import ReplayObservation


@dataclass
class StubReplayer:
    """Returns a fixed observation — a deterministic stand-in for live re-execution."""

    observation: ReplayObservation

    def replay(self, evidence: Evidence) -> ReplayObservation:  # noqa: ARG002 - fixed stub
        return self.observation


def _evidence() -> Evidence:
    return Evidence(
        id="e1",
        kind="proxy_exchange",
        evidence_refs=["101"],
        replay=EvidenceReplay(medium="http", inputs={"method": "GET", "url": "http://x/y"}),
    )


def _finding() -> Finding:
    return Finding(id="f1", title="candidate", evidence_ids=["e1"])


# ── the four oracle shapes: signal confirms, absence rejects ─────────────────


def test_canary_read_oracle_confirms_on_signal_and_rejects_without() -> None:
    canary = mint_canary()
    exp = OracleExpectation(shape="canary_read", value=canary)

    confirmed = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, response_text=f"...{canary}..."))
    ).validate(_finding(), _evidence(), exp, author="validator-1")
    assert confirmed.passed and not confirmed.reach_only
    assert confirmed.oracle_signal["canary"] == canary

    rejected = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, response_text="200 OK, nothing protected"))
    ).validate(_finding(), _evidence(), exp, author="validator-1")
    assert rejected.passed is False and rejected.reach_only is True


def test_effect_oracle_confirms_on_readback_and_rejects_without() -> None:
    exp = OracleExpectation(shape="effect_observed", value="oob-callback-7f3a")
    confirmed = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, effect_readback="saw oob-callback-7f3a"))
    ).validate(_finding(), _evidence(), exp, author="v")
    assert confirmed.passed
    rejected = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, effect_readback=""))
    ).validate(_finding(), _evidence(), exp, author="v")
    assert rejected.passed is False and rejected.reach_only is True


def test_differential_oracle_requires_the_difference_not_a_shared_artifact() -> None:
    exp = OracleExpectation(shape="differential", value="DELAYED")
    confirmed = ValidatorLibrary(
        StubReplayer(
            ReplayObservation(reached=True, response_text="DELAYED", negative_control_text="FAST")
        )
    ).validate(_finding(), _evidence(), exp, author="v")
    assert confirmed.passed
    # Marker present under BOTH exploit and control is an environmental artifact, not a signal.
    shared = ValidatorLibrary(
        StubReplayer(
            ReplayObservation(
                reached=True, response_text="DELAYED", negative_control_text="DELAYED"
            )
        )
    ).validate(_finding(), _evidence(), exp, author="v")
    assert shared.passed is False and shared.reach_only is True


def test_crash_signature_oracle_confirms_on_signature_and_rejects_without() -> None:
    signature = "AddressSanitizer: heap-buffer-overflow"
    exp = OracleExpectation(shape="crash_signature", value=signature)
    confirmed = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, crash_output=f"==ERROR {signature}"))
    ).validate(_finding(), _evidence(), exp, author="v")
    assert confirmed.passed
    rejected = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, crash_output="exit code 0"))
    ).validate(_finding(), _evidence(), exp, author="v")
    assert rejected.passed is False and rejected.reach_only is True


# ── THE mandatory distinction: reached-the-surface vs performed-the-exploit ──


def test_reached_surface_without_oracle_signal_is_rejected_but_with_signal_is_confirmed() -> None:
    """Mandatory (the Target-B lesson). Two candidates with identical evidence
    differ only in what the re-execution observes:

    * one reaches the surface but the re-executed response carries no oracle
      signal — it reached the tier, it did not perform the exploit — REJECTED
      (``reach_only``);
    * one's re-executed response carries the oracle signal — it performed the
      exploit and the effect was observed — CONFIRMED.

    The validator distinguishes them by exactly that: the presence or absence of
    the re-observed oracle signal. A signature/trace oracle, which would see the
    same surface reached in both, cannot.
    """
    canary = mint_canary()
    exp = OracleExpectation(shape="canary_read", value=canary)
    finding, evidence = _finding(), _evidence()

    reached_only = ValidatorLibrary(
        # The re-execution reached the surface (a real 200 response) but the
        # protected value never appears — the exploit was not performed.
        StubReplayer(ReplayObservation(reached=True, response_text="HTTP/1.1 200 OK\n<index page>"))
    ).validate(finding, evidence, exp, author="validator-1")

    performed = ValidatorLibrary(
        # The same surface, but now the re-executed response carries the planted
        # canary — the protected read actually happened.
        StubReplayer(
            ReplayObservation(reached=True, response_text=f"HTTP/1.1 200 OK\nsecret={canary}")
        )
    ).validate(finding, evidence, exp, author="validator-1")

    assert reached_only.passed is False and reached_only.reach_only is True
    assert "REACH-ONLY" in reached_only.detail
    assert performed.passed is True and performed.reach_only is False
    assert performed.oracle_signal["canary"] == canary


# ── fabricated / false candidates are rejected ───────────────────────────────


def test_a_replay_that_never_reaches_the_surface_yields_no_confirmation() -> None:
    @dataclass
    class DeadReplayer:
        def replay(self, evidence: Evidence) -> ReplayObservation:  # noqa: ARG002
            return ReplayObservation(reached=False)

    verdict = ValidatorLibrary(DeadReplayer()).validate(
        _finding(), _evidence(), OracleExpectation(shape="canary_read", value=mint_canary()),
        author="v",
    )
    assert verdict.passed is False
    assert verdict_confirms(verdict) is False


def test_llm_prefilter_may_only_downgrade_never_confirm() -> None:
    canary = mint_canary()
    exp = OracleExpectation(shape="canary_read", value=canary)
    # Even with an observation that WOULD confirm, a pre-filter that rejects wins —
    # the pre-filter can only reject, and the oracle is the final gate otherwise.
    verdict = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, response_text=canary)),
        prefilter=lambda finding, evidence: False,  # noqa: ARG005
    ).validate(_finding(), _evidence(), exp, author="v")
    assert verdict.passed is False


# ── integration: only a passing verdict carries a finding to confirmed ───────


def test_a_planted_false_candidate_cannot_reach_confirmed_in_the_ledger() -> None:
    ledger = ResearchLedger(":memory:")
    ledger.record_evidence(_evidence())
    ledger.record_finding(_finding())

    exp = OracleExpectation(shape="canary_read", value=mint_canary())
    reach_only = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, response_text="no secret here"))
    ).validate(_finding(), _evidence(), exp, author="validator-1")

    # The reach-only verdict cannot confirm — the ledger refuses it.
    try:
        ledger.confirm_finding("f1", reach_only)
        raise AssertionError("a reach-only verdict must not confirm a finding")
    except VerdictError:
        pass
    assert ledger.get_finding("f1").state == "open"


def test_a_real_candidate_reaches_confirmed_through_a_passing_verdict() -> None:
    ledger = ResearchLedger(":memory:")
    ledger.record_evidence(_evidence())
    ledger.record_finding(_finding())
    canary = mint_canary()
    verdict = ValidatorLibrary(
        StubReplayer(ReplayObservation(reached=True, response_text=f"leaked {canary}"))
    ).validate(_finding(), _evidence(), OracleExpectation(shape="canary_read", value=canary),
               author="validator-1")
    confirmed = ledger.confirm_finding("f1", verdict)
    assert confirmed.state == "confirmed"
    assert confirmed.validator_verdict_id == verdict.id
    assert confirmed.verdict_author == "validator-1"
