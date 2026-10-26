"""Unit tests for the typed hunt-handoff contracts (item 1.2).

:class:`HuntTask` is the parent→hunter delegation contract and :class:`HuntReport`
is the hunter→parent result. These tests pin the structural guarantees: exactly
one known vulnerability class, surface references that resolve to known surfaces,
a required scope, a confirmed finding obliging a root cause, and a round-trip
through JSON serialization.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from zen.skills import get_vulnerability_class_names
from zen.tools.agents_graph.contracts import HuntReport, HuntScope, HuntTask


def _valid_task_kwargs() -> dict[str, object]:
    """A minimal, well-formed HuntTask as keyword args."""
    return {
        "objective": "Prosecute the reflected parameter against the search surface.",
        "vuln_class": "xss",
        "basis": "observed",
        "depth_tier": "deep",
        "impact_objective": "primitive",
        "scope": HuntScope(allow=["surface-1"]),
        "surface_refs": ["surface-1"],
    }


# --- HuntTask: single vuln_class -------------------------------------------------


def test_single_vuln_class_round_trips() -> None:
    task = HuntTask(**_valid_task_kwargs())
    restored = HuntTask.model_validate_json(task.model_dump_json())
    assert restored.vuln_class == "xss"
    assert restored.scope.allow == ["surface-1"]
    assert restored.depth_tier == "deep"


def test_two_vuln_class_values_are_rejected() -> None:
    kwargs = _valid_task_kwargs()
    kwargs["vuln_class"] = ["xss", "ssrf"]  # more than one class
    with pytest.raises(ValidationError):
        HuntTask(**kwargs)


def test_unknown_vuln_class_is_rejected() -> None:
    kwargs = _valid_task_kwargs()
    kwargs["vuln_class"] = "definitely_not_a_shipped_class"
    with pytest.raises(ValidationError):
        HuntTask(**kwargs)


def test_vuln_class_set_is_derived_from_the_catalog() -> None:
    # Derived generically from vulnerabilities/*, excluding the *_deep siblings.
    classes = get_vulnerability_class_names()
    assert "xss" in classes
    assert "ssrf" in classes
    assert not any(name.endswith("_deep") for name in classes)


# --- HuntTask: surface refs resolve ----------------------------------------------


def test_unknown_surface_ref_is_rejected_against_known_set() -> None:
    kwargs = _valid_task_kwargs()
    kwargs["surface_refs"] = ["surface-1", "ghost-surface"]
    with pytest.raises(ValidationError):
        HuntTask.model_validate(
            {**kwargs, "scope": {"allow": ["surface-1"]}},
            context={"known_surface_ids": {"surface-1"}},
        )


def test_surface_refs_accepted_when_all_resolve() -> None:
    kwargs = _valid_task_kwargs()
    kwargs["surface_refs"] = ["surface-1", "surface-2"]
    task = HuntTask.model_validate(
        {**kwargs, "scope": {"allow": ["surface-1"]}},
        context={"known_surface_ids": {"surface-1", "surface-2"}},
    )
    assert task.surface_refs == ["surface-1", "surface-2"]


def test_surface_refs_not_enforced_without_a_known_set() -> None:
    # No context → membership cannot be resolved → not a reason to reject.
    kwargs = _valid_task_kwargs()
    kwargs["surface_refs"] = ["anything"]
    task = HuntTask(**kwargs)
    assert task.surface_refs == ["anything"]


# --- HuntTask: scope present -----------------------------------------------------


def test_scope_is_required() -> None:
    kwargs = _valid_task_kwargs()
    del kwargs["scope"]
    with pytest.raises(ValidationError):
        HuntTask(**kwargs)


def test_render_block_is_class_agnostic_structured_text() -> None:
    task = HuntTask(**_valid_task_kwargs(), rationale="Direct route looks cheaper than the chain.")
    block = task.render_block()
    assert "== Hunt Task (structured delegation contract) ==" in block
    assert "Vulnerability class (exactly one): xss" in block
    # basis is grounding, labelled as such — never a difficulty tier.
    assert "evidentiary grounding, not difficulty" in block
    assert "Impact objective (ladder rung to reach): primitive" in block
    # The free-text rationale rides along, marked as context not contract.
    assert "Parent rationale (context, not contract):" in block
    assert block.strip().endswith("== End hunt task ==")


# --- HuntReport ------------------------------------------------------------------


def test_confirmed_finding_requires_root_cause() -> None:
    with pytest.raises(ValidationError):
        HuntReport(filed_report_ids=["vuln-1"])  # no root_cause


def test_confirmed_finding_with_root_cause_is_accepted() -> None:
    report = HuntReport(
        filed_report_ids=["vuln-1"],
        root_cause="User input reaches the sink without contextual output encoding.",
        impact_reached="weaponized",
        variant_leads=["second-order variant via the stored field"],
    )
    assert report.filed_report_ids == ["vuln-1"]


def test_report_with_no_finding_needs_no_root_cause() -> None:
    report = HuntReport(impact_reached="reach", open_items=["could not obtain a second tenant"])
    assert report.root_cause == ""
    assert report.filed_report_ids == []


def test_digest_carries_impact_reached_and_variant_leads() -> None:
    report = HuntReport(
        impact_reached="primitive",
        variant_leads=["parser-differential variant", "nested-context variant"],
    )
    digest = report.digest()
    assert digest["impact_reached"] == "primitive"
    assert digest["variant_leads"] == ["parser-differential variant", "nested-context variant"]


def test_report_round_trips_through_json() -> None:
    report = HuntReport(
        hypotheses_tested=["h1"],
        evidence_ids=["ev-1", "ev-2"],
        impact_reached="chained",
        filed_report_ids=["vuln-9"],
        root_cause="Trust boundary crossed without re-authorization.",
    )
    restored = HuntReport.model_validate_json(report.model_dump_json())
    assert restored.impact_reached == "chained"
    assert restored.evidence_ids == ["ev-1", "ev-2"]
