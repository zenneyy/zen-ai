"""Unit tests for the structured Hypothesis / Finding records (item 1.3).

These pin the schema-level guarantees that the save gate and the generated
persona CONTRACT both build on: the basis-conditional required fields, the
evidence-id shape and bounded resolution, the ``confirmed`` finding gate, and
the in-markdown convention the parser reads. Everything here is class-agnostic —
no specific vulnerability, technique, or scenario stands in as the subject.
"""

from __future__ import annotations

from typing import Any, get_args

import pytest
from pydantic import ValidationError

from zen.tools.agents_graph.contracts import HuntBasis
from zen.tools.threat_model.schema import (
    HYPOTHESIS_BASIS_VALUES,
    HYPOTHESIS_CONVENTION,
    HYPOTHESIS_DISPOSITION_VALUES,
    REFUTATION_BASIS_VALUES,
    Finding,
    Hypothesis,
    HypothesisDisposition,
    RefutationBasis,
    parse_hypotheses,
    referenced_evidence_ids,
    refutation_problem,
    ungrounded_refutations,
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


# --- refutation grounds: `refuted` states why --------------------------------------

_REASONING_BASES = ("control_verified", "sink_inert", "input_trusted", "not_applicable")


def test_refutation_bases_are_one_small_class_agnostic_set() -> None:
    assert get_args(RefutationBasis) == REFUTATION_BASIS_VALUES
    assert set(REFUTATION_BASIS_VALUES) == {"attack_failed", *_REASONING_BASES}


def test_a_refuted_hypothesis_without_a_basis_still_loads_and_is_named() -> None:
    # Not a validator: a lead saved before the rule existed must still load, so the
    # gates can name it instead of crashing on it or losing sight of it.
    problem = refutation_problem(Hypothesis(id="H1", basis="assumed", state="refuted"))
    assert problem is not None
    assert "refutation_basis" in problem


@pytest.mark.parametrize("state", ["open", "testing", "blocked", "confirmed"])
def test_only_a_refuted_state_owes_refutation_grounds(state: str) -> None:
    assert refutation_problem(Hypothesis(id="H", basis="assumed", state=state)) is None


@pytest.mark.parametrize(
    "grounds",
    [
        {"refuting_evidence_ids": ["101"]},
        {"refutation": "the crafted request was sent and rejected before the handler ran"},
        {"refuting_evidence_ids": ["101"], "refutation": "sent and rejected at the parser"},
    ],
    ids=["evidence-ids", "statement", "both"],
)
def test_attack_failed_rests_on_evidence_ids_or_a_statement(grounds: dict[str, Any]) -> None:
    hypothesis = Hypothesis(
        id="H", basis="assumed", state="refuted", refutation_basis="attack_failed", **grounds
    )
    assert refutation_problem(hypothesis) is None


def test_attack_failed_with_neither_evidence_nor_statement_is_a_problem() -> None:
    hypothesis = Hypothesis(
        id="H", basis="assumed", state="refuted", refutation_basis="attack_failed"
    )
    assert "attack_failed" in (refutation_problem(hypothesis) or "")


@pytest.mark.parametrize("basis", _REASONING_BASES)
def test_a_reasoned_refutation_needs_its_statement_even_with_evidence_ids(basis: str) -> None:
    bare = Hypothesis(
        id="H",
        basis="assumed",
        state="refuted",
        refutation_basis=basis,
        refuting_evidence_ids=["101"],
    )
    assert "refutation:" in (refutation_problem(bare) or "")
    stated = bare.model_copy(update={"refutation": "the check runs before the effect"})
    assert refutation_problem(stated) is None


def test_a_blank_statement_is_no_statement() -> None:
    hypothesis = Hypothesis(
        id="H", basis="assumed", state="refuted", refutation_basis="sink_inert", refutation="  "
    )
    assert refutation_problem(hypothesis) is not None


@pytest.mark.parametrize(
    ("written", "canonical"),
    [
        ("attack_failed", "attack_failed"),
        ("Attack-Failed", "attack_failed"),
        ("Not Applicable", "not_applicable"),
    ],
)
def test_refutation_basis_normalizes_organic_spellings(written: str, canonical: str) -> None:
    hypothesis = Hypothesis(id="H", basis="assumed", state="refuted", refutation_basis=written)
    assert hypothesis.refutation_basis == canonical


def test_an_unknown_refutation_basis_is_rejected_listing_valid_values() -> None:
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis(id="H", basis="assumed", state="refuted", refutation_basis="not_pursued")
    message = str(excinfo.value)
    assert "refutation_basis" in message
    assert "attack_failed" in message


def test_refuting_evidence_ids_resolve_like_supporting_ids() -> None:
    raw = {
        "id": "H5",
        "basis": "assumed",
        "state": "refuted",
        "refutation_basis": "attack_failed",
        "refuting_evidence_ids": ["101", "999"],
    }
    with pytest.raises(ValidationError) as excinfo:
        Hypothesis.model_validate(raw, context={"known_evidence_ids": {"101"}})
    message = str(excinfo.value)
    assert "H5" in message
    assert "refuting_evidence_ids" in message
    assert "999" in message
    # No known set in context: shape only, never rejected wholesale.
    assert Hypothesis.model_validate(raw).refuting_evidence_ids == ["101", "999"]


def test_referenced_evidence_ids_include_refuting_ids() -> None:
    markdown = (
        "## Hypotheses\n"
        "- id: H1 | basis: observed | supporting_evidence_ids: 101 | state: refuted | "
        "refutation_basis: attack_failed | refuting_evidence_ids: 202, 101\n"
    )
    assert referenced_evidence_ids(markdown) == ["101", "202"]


def test_parse_hypotheses_reads_refutation_grounds_and_names_ungrounded_ones() -> None:
    hyps, errors = parse_hypotheses(
        "## Hypotheses\n"
        "- id: H1 | basis: assumed | state: refuted | refutation_basis: control_verified | "
        "refutation: the check runs before the effect on every path\n"
        "- id: H2 | basis: assumed | state: refuted\n"
        "- id: H3 | basis: assumed | state: refuted | refutation_basis: input_trusted\n"
    )
    # Parsing is unchanged: an ungrounded refutation is well-formed as a record...
    assert errors == []
    assert hyps[0].refutation_basis == "control_verified"
    # ...and the grounds rule names every offender at once.
    named = ungrounded_refutations(hyps)
    assert [e.hypothesis_id for e in named] == ["H2", "H3"]
    assert "refutation_basis" in named[0].message
    assert "input_trusted" in named[1].message


def test_an_ungrounded_refutation_that_carries_a_disposition_is_told_both_fixes() -> None:
    hypothesis = Hypothesis(
        id="H", basis="assumed", state="refuted", disposition="resolved_elsewhere"
    )
    problem = refutation_problem(hypothesis) or ""
    assert "refutation_basis" in problem
    assert "disposition: resolved_elsewhere" in problem
    assert "back to open or blocked" in problem
    # Without a disposition there is only one fix to name.
    bare = refutation_problem(Hypothesis(id="H", basis="assumed", state="refuted")) or ""
    assert "back to open or blocked" not in bare
