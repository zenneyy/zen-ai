"""The clean-context reviewer (Phase 2, item 2.2).

The reviewer confirms the classes with no mechanical oracle — authorization,
business logic — by re-observing a role/tenant/state differential *itself*, from a
context that deliberately excludes the hunter's narrative. These prove it catches
a seeded isolation regression it was never told about, grounds its verdict in what
it re-observed rather than in any story, and that a passing verdict carries a
finding to ``confirmed`` through the same ledger gate.

Class-agnostic throughout: principals and a resource marker, never a named class.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zen.tools.ledger import Evidence, Finding, ResearchLedger
from zen.validation import CleanContextReviewer, DifferentialProbe, ReviewInput
from zen.validation.ground_truth import mint_canary
from zen.validation.oracles import ReplayObservation


@dataclass
class StubPrincipalReplayer:
    """Replays evidence as a principal; a configured set of principals reach the marker."""

    marker: str
    reaching_principals: set[str] = field(default_factory=set)

    def replay_as(self, evidence: Evidence, principal: str) -> ReplayObservation:  # noqa: ARG002
        body = f"{principal} response"
        if principal in self.reaching_principals:
            body += f" :: {self.marker}"
        return ReplayObservation(reached=True, response_text=body)


def _evidence() -> Evidence:
    return Evidence(id="e1", kind="proxy_exchange", evidence_refs=["55"])


def _review_input(marker: str) -> ReviewInput:
    return ReviewInput(
        finding_id="f1",
        evidence=_evidence(),
        target="https://app.example.test",
        # The probe names only WHAT to compare — never a claim that a bug exists.
        probe=DifferentialProbe(
            principal_under_test="tenant-b",
            control_principal="tenant-a",
            resource_marker=marker,
        ),
    )


def test_review_input_carries_no_hunter_narrative() -> None:
    """Clean context is structural: there is no field to carry the hunter's story,
    so the reviewer cannot be led by it."""
    fields = set(ReviewInput.__dataclass_fields__)
    assert fields == {"finding_id", "evidence", "target", "probe"}
    for leaky in ("narrative", "reasoning", "hypothesis", "author_reasoning", "rationale"):
        assert leaky not in fields


def test_reviewer_catches_a_seeded_regression_it_was_not_told_about() -> None:
    marker = mint_canary()  # planted only in tenant-a's resource
    # The seeded regression: tenant-b (should be isolated) ALSO reaches the marker.
    replayer = StubPrincipalReplayer(marker, reaching_principals={"tenant-a", "tenant-b"})
    verdict = CleanContextReviewer(replayer).review(_review_input(marker), author="reviewer-1")

    assert verdict.passed is True
    assert verdict.oracle == "reviewer_differential"
    # The verdict is grounded in the re-observed differential, not a narrative.
    assert "tenant-b" in verdict.oracle_signal["differential"]
    assert "tenant-a" in verdict.oracle_signal["differential"]


def test_reviewer_rejects_when_isolation_holds() -> None:
    marker = mint_canary()
    # Only the owner reaches the marker — isolation holds, no regression.
    replayer = StubPrincipalReplayer(marker, reaching_principals={"tenant-a"})
    verdict = CleanContextReviewer(replayer).review(_review_input(marker), author="reviewer-1")
    assert verdict.passed is False
    assert verdict.reach_only is False  # the baseline held; it is a real rejection


def test_reviewer_is_inconclusive_when_the_baseline_does_not_hold() -> None:
    marker = mint_canary()
    # Not even the owner reaches the marker: the probe's baseline is broken, so no
    # isolation claim can be grounded either way.
    replayer = StubPrincipalReplayer(marker, reaching_principals=set())
    verdict = CleanContextReviewer(replayer).review(_review_input(marker), author="reviewer-1")
    assert verdict.passed is False
    assert verdict.reach_only is True


def test_a_reviewer_verdict_confirms_a_finding_in_the_ledger() -> None:
    ledger = ResearchLedger(":memory:")
    ledger.record_evidence(_evidence())
    ledger.record_finding(Finding(id="f1", evidence_ids=["e1"]))
    marker = mint_canary()
    verdict = CleanContextReviewer(
        StubPrincipalReplayer(marker, reaching_principals={"tenant-a", "tenant-b"})
    ).review(_review_input(marker), author="reviewer-1")
    confirmed = ledger.confirm_finding("f1", verdict)
    assert confirmed.state == "confirmed"
    assert confirmed.verdict_author == "reviewer-1"
