"""Unit tests for the structured Hypothesis / Finding records (item 1.3).

These pin the schema-level guarantees that the save gate and the generated
persona CONTRACT both build on: the basis-conditional required fields, the
evidence-id shape and bounded resolution, the ``confirmed`` finding gate, and
the in-markdown convention the parser reads. Everything here is class-agnostic —
no specific vulnerability, technique, or scenario stands in as the subject.
"""

from __future__ import annotations

from typing import get_args

import pytest
from pydantic import ValidationError

from zen.tools.agents_graph.contracts import HuntBasis
from zen.tools.threat_model.schema import (
    HYPOTHESIS_BASIS_VALUES,
    HYPOTHESIS_CONVENTION,
    HYPOTHESIS_DISPOSITION_VALUES,
    Finding,
    Hypothesis,
    HypothesisDisposition,
    parse_hypotheses,
    referenced_evidence_ids,
)


# --- basis is grounding, enforced; depth lives elsewhere -------------------------


def test_basis_values_track_the_delegation_contract() -> None:
    # One definition of basis: the schema reuses the contract's Literal verbatim.
    assert get_args(HuntBasis) == HYPOTHESIS_BASIS_VALUES
    assert set(HYPOTHESIS_BASIS_VALUES) == {"observed", "inferred_from_architecture", "assumed"}


def test_observed_requires_supporting_evidence_and_names_the_hypothesis() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis(id="H7", basis="observed")
    message = str(excinfo.value)
    assert "H7" in message
    assert "supporting_evidence_id" in message


def test_inferred_from_architecture_requires_an_inference_chain() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis(id="H8", basis="inferred_from_architecture")
    assert "inference_chain" in str(excinfo.value)


def test_assumed_needs_neither_evidence_nor_chain() -> None:
    hypothesis = Hypothesis(id="H9", basis="assumed")
    assert hypothesis.supporting_evidence_ids == []
    assert hypothesis.inference_chain == []


def test_well_formed_observed_hypothesis_passes() -> None:
    hypothesis = Hypothesis(
        id="H1",
        basis="observed",
        supporting_evidence_ids=["101", "102"],
        target_depth="deep",
        impact_objective="primitive",
    )
    assert hypothesis.basis == "observed"
    # Depth/ambition is a separate axis from grounding.
    assert hypothesis.target_depth == "deep"
    assert hypothesis.impact_objective == "primitive"


def test_depth_lives_in_target_depth_not_basis() -> None:
    # The same basis admits every depth tier — grounding does not cap depth.
    for depth in ("confirm", "discover", "deep"):
        hypothesis = Hypothesis(id="H", basis="assumed", target_depth=depth)
        assert hypothesis.target_depth == depth


# --- evidence-id shape and bounded resolution ------------------------------------


def test_evidence_id_shape_rejects_whitespace_tokens() -> None:
    with pytest.raises(ValidationError):
        Hypothesis(id="H", basis="observed", supporting_evidence_ids=["not an id"])


def test_evidence_resolution_skipped_without_a_known_set() -> None:
    # No context → membership cannot be resolved → shape only, never rejected.
    hypothesis = Hypothesis.model_validate(
        {"id": "H", "basis": "observed", "supporting_evidence_ids": ["424242"]},
        context={"known_evidence_ids": None},
    )
    assert hypothesis.supporting_evidence_ids == ["424242"]


def test_evidence_resolution_rejects_ids_outside_a_known_set() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis.model_validate(
            {"id": "H5", "basis": "observed", "supporting_evidence_ids": ["101", "999"]},
            context={"known_evidence_ids": {"101"}},
        )
    message = str(excinfo.value)
    assert "H5" in message
    assert "999" in message


def test_evidence_resolution_accepts_ids_in_the_known_set() -> None:
    hypothesis = Hypothesis.model_validate(
        {"id": "H", "basis": "observed", "supporting_evidence_ids": ["101", "102"]},
        context={"known_evidence_ids": {"101", "102"}},
    )
    assert hypothesis.supporting_evidence_ids == ["101", "102"]


# --- Finding: confirmed is unreachable without a verdict -------------------------


def test_finding_confirmed_requires_verdict_and_author() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Finding(id="F1", state="confirmed")
    assert "validator_verdict_id" in str(excinfo.value)


def test_finding_confirmed_requires_both_verdict_and_author() -> None:
    # A verdict id without an author is still not a confirmation.
    with pytest.raises(ValidationError):
        Finding(id="F2", state="confirmed", validator_verdict_id="v-1")


def test_finding_confirmed_with_verdict_and_author_is_accepted() -> None:
    finding = Finding(
        id="F3",
        state="confirmed",
        validator_verdict_id="v-1",
        verdict_author="validator-agent",
    )
    assert finding.state == "confirmed"


def test_hunter_candidate_states_need_no_verdict() -> None:
    for state in ("open", "testing"):
        finding = Finding(id="F", state=state)
        assert finding.state == state


# --- the in-markdown convention and its parser -----------------------------------

_HYPOTHESES_MARKDOWN = """# Threat Model

## Observations
Something was observed.

## Hypotheses
- id: H1 | basis: observed | mechanism: input reaches a sink | predicted_observable: the sink fires | supporting_evidence_ids: 101, 102 | target_depth: discover | impact_objective: primitive | rationale: seen during enumeration
- id: H2 | basis: inferred_from_architecture | mechanism: a boundary is crossed | predicted_observable: the crossing is reachable | inference_chain: the documented stages pass a request on; a later stage trusts the earlier one | target_depth: deep | impact_objective: chained | rationale: implied by the stage layout
- id: H3 | basis: assumed | mechanism: a surface may be exposed | predicted_observable: it answers | target_depth: confirm | impact_objective: reach

## Severity Calibration
Levels here.
"""


def test_parse_hypotheses_reads_every_entry() -> None:
    hypotheses, errors = parse_hypotheses(_HYPOTHESES_MARKDOWN)
    assert errors == []
    assert [h.id for h in hypotheses] == ["H1", "H2", "H3"]
    assert hypotheses[0].supporting_evidence_ids == ["101", "102"]
    assert len(hypotheses[1].inference_chain) == 2


def test_parse_hypotheses_names_a_malformed_entry() -> None:
    broken = _HYPOTHESES_MARKDOWN.replace("basis: observed | ", "")  # H1 loses its basis
    hypotheses, errors = parse_hypotheses(broken)
    assert [h.id for h in hypotheses] == ["H2", "H3"]
    assert [e.hypothesis_id for e in errors] == ["H1"]
    assert "basis" in errors[0].message


def test_parse_hypotheses_threads_the_known_evidence_set() -> None:
    _, errors = parse_hypotheses(_HYPOTHESES_MARKDOWN, known_evidence_ids={"101"})  # 102 unknown
    assert [e.hypothesis_id for e in errors] == ["H1"]
    assert "102" in errors[0].message


def test_referenced_evidence_ids_collects_supporting_ids() -> None:
    assert referenced_evidence_ids(_HYPOTHESES_MARKDOWN) == ["101", "102"]


def test_convention_describe_mentions_basis_and_the_conditional_fields() -> None:
    described = "\n".join(HYPOTHESIS_CONVENTION.describe())
    assert "basis" in described
    assert "supporting_evidence_ids" in described
    assert "inference_chain" in described
    # The grounding-vs-depth distinction is stated, not implied.
    assert "not a difficulty" in described or "not in `basis`" in described


# --- hypothesis disposition: the inline closure-gate channel ---------------------


def test_disposition_values_are_a_small_class_agnostic_set() -> None:
    # One source: the tuple is derived from the Literal, so they cannot diverge.
    assert get_args(HypothesisDisposition) == HYPOTHESIS_DISPOSITION_VALUES
    assert set(HYPOTHESIS_DISPOSITION_VALUES) == {
        "deferred",
        "accepted_risk",
        "out_of_scope",
        "resolved_elsewhere",
    }


def test_disposition_is_optional_and_unset_by_default() -> None:
    # A hypothesis needs no disposition; confirmed/refuted/testing never do.
    assert Hypothesis(id="H", basis="assumed").disposition is None


@pytest.mark.parametrize(
    ("written", "canonical"),
    [
        ("deferred", "deferred"),
        ("Deferred", "deferred"),
        ("accepted-risk", "accepted_risk"),
        ("Out Of Scope", "out_of_scope"),
        ("resolved_elsewhere", "resolved_elsewhere"),
    ],
)
def test_disposition_normalizes_organic_spellings(written: str, canonical: str) -> None:
    assert Hypothesis(id="H", basis="assumed", disposition=written).disposition == canonical


def test_blank_disposition_is_unset_not_an_error() -> None:
    # An empty value means the field was left blank — no disposition, not a bad one.
    assert Hypothesis(id="H", basis="assumed", disposition="").disposition is None


def test_unknown_disposition_is_rejected_listing_valid_values() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis(id="H", basis="assumed", disposition="maybe_later")
    message = str(excinfo.value)
    assert "disposition" in message
    assert "deferred" in message


def test_parse_hypotheses_reads_an_inline_disposition() -> None:
    hyps, errors = parse_hypotheses(
        "## Hypotheses\n"
        "- id: H1 | basis: assumed | state: open | disposition: deferred | "
        "disposition_reason: carried forward\n"
    )
    assert errors == []
    assert hyps[0].disposition == "deferred"
    assert hyps[0].disposition_reason == "carried forward"
