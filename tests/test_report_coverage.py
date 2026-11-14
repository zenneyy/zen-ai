"""Tests for the coverage artifact assembled in zen.report.coverage."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

import pytest

from zen.report.coverage import (
    _SKILL_PHRASINGS,
    build_coverage_document,
    read_agent_graph,
    unrecorded_hunt_classes,
    write_coverage,
)
from zen.skills import get_available_skills


if TYPE_CHECKING:
    from pathlib import Path


def _entry(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "surface": "POST /api/orders/{id}",
        "risk_area": "object-level authorization",
        "outcome": "no_issue_found",
        "evidence": "Two tenants tested; both received 403.",
        "agent_id": "agent-1",
        "agent_name": "authz-tester",
        "created_at": "2026-07-02 10:00:00 UTC",
    }
    base.update(overrides)
    return base


def _graph(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "statuses": {"agent-1": "completed"},
        "names": {"agent-1": "authz-tester"},
        "metadata": {"agent-1": {"skills": ["idor"], "task": "authz review"}},
    }
    base.update(overrides)
    return base


def _document(**overrides: Any) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "run_record": {"run_id": "r1", "run_name": "run-1", "status": "completed"},
        "entries": [_entry()],
        "agent_graph": _graph(),
        "vulnerability_reports": [],
    }
    kwargs.update(overrides)
    return build_coverage_document(**kwargs)


def test_document_reports_surfaces_and_outcomes() -> None:
    doc = _document()

    assert doc["summary"]["surfaces_reviewed"] == 1
    assert doc["summary"]["outcomes"] == {"no_issue_found": 1}
    assert doc["entries"][0]["outcome_label"] == "No issue identified"
    assert doc["entries"][0]["recorded_by"] == "authz-tester"


def test_ledger_entries_are_labelled_as_agent_reported() -> None:
    """A reader has to be able to tell a self-report from an observation."""
    doc = _document()

    assert doc["entries"][0]["source"] == "agent_reported"
    assert doc["machine_observed"]["source"] == "runtime"
    assert doc["machine_observed"]["skills_exercised"] == ["idor"]


def test_assigned_risk_skill_without_coverage_becomes_a_gap() -> None:
    """An agent carrying the sql_injection skill that records nothing about it
    leaves the class unexamined, not clean."""
    doc = _document(
        agent_graph=_graph(
            metadata={"agent-1": {"skills": ["idor", "sql_injection"], "task": "review"}}
        )
    )

    gaps = [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]
    assert [gap["risk_area"] for gap in gaps] == ["sql injection"]


def test_recorded_risk_class_is_not_reported_as_a_gap() -> None:
    doc = _document(
        entries=[_entry(risk_area="SQL injection", surface="GET /search?q=")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["sql_injection"]}}),
    )

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def test_synonym_phrasing_counts_as_recorded_coverage() -> None:
    """The ledger says "object-level authorization"; the skill is called idor."""
    doc = _document(agent_graph=_graph(metadata={"agent-1": {"skills": ["idor"]}}))

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def test_non_risk_skills_carry_no_coverage_obligation() -> None:
    """Tooling skills describe how an agent works, not what it hunts."""
    doc = _document(agent_graph=_graph(metadata={"agent-1": {"skills": ["idor", "caido"]}}))

    assert not [gap for gap in doc["gaps"] if gap.get("risk_area") == "caido"]


def test_agent_that_recorded_nothing_is_a_gap() -> None:
    doc = _document(
        agent_graph=_graph(
            statuses={"agent-1": "completed", "agent-2": "completed"},
            names={"agent-1": "authz-tester", "agent-2": "recon"},
            metadata={},
        )
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["recon"]


def test_needs_follow_up_is_carried_as_an_open_gap() -> None:
    doc = _document(
        entries=[_entry(outcome="needs_follow_up", evidence="Auth wall blocked testing.")]
    )

    assert doc["gaps"][0]["kind"] == "needs_follow_up"
    assert doc["gaps"][0]["detail"] == "Auth wall blocked testing."


def test_completed_run_with_finished_agents_is_complete() -> None:
    doc = _document(exit_reason="finished_by_tool")

    assert doc["completeness"]["complete"] is True
    assert doc["completeness"]["caveats"] == []


def test_budget_exhausted_run_is_not_a_complete_record() -> None:
    """A truncated scan must not read like a clean one."""
    doc = _document(exit_reason="budget_exhausted")

    assert doc["completeness"]["complete"] is False
    assert "budget_exhausted" in doc["completeness"]["caveats"][0]


def test_unfinished_agent_makes_the_record_partial() -> None:
    doc = _document(
        agent_graph=_graph(statuses={"agent-1": "crashed"}),
        exit_reason="finished_by_tool",
    )

    assert doc["completeness"]["complete"] is False
    assert "authz-tester" in doc["completeness"]["caveats"][0]


def test_failed_run_status_makes_the_record_partial() -> None:
    doc = _document(
        run_record={"run_id": "r1", "status": "failed"},
        exit_reason="finished_by_tool",
    )

    assert doc["completeness"]["complete"] is False


def test_write_coverage_emits_a_top_level_artifact(tmp_path: Path) -> None:
    path = write_coverage(tmp_path, _document())

    assert path == tmp_path / "coverage.json"
    assert json.loads(path.read_text(encoding="utf-8"))["schema_version"] == 1


def test_read_agent_graph_tolerates_a_missing_or_corrupt_snapshot(tmp_path: Path) -> None:
    assert read_agent_graph(tmp_path) == {}

    (tmp_path / "agents.json").write_text("{not json", encoding="utf-8")
    assert read_agent_graph(tmp_path) == {}


def test_read_agent_graph_loads_a_snapshot(tmp_path: Path) -> None:
    (tmp_path / "agents.json").write_text(json.dumps(_graph()), encoding="utf-8")

    assert read_agent_graph(tmp_path)["names"] == {"agent-1": "authz-tester"}


def test_multi_token_skill_matches_how_a_pentester_writes_it() -> None:
    """An agent carrying path_traversal_lfi_rfi records "Path Traversal".

    Requiring the skill's filename verbatim published a false gap for a class
    that had been tested and even had a finding filed against it.
    """
    doc = _document(
        entries=[_entry(risk_area="Path Traversal / Directory Traversal", surface="/download")],
        agent_graph=_graph(metadata={"agent-1": {"skills": ["path_traversal_lfi_rfi"]}}),
    )

    assert not [gap for gap in doc["gaps"] if gap["kind"] == "unrecorded_risk_class"]


def _vulnerability_skill_names() -> set[str]:
    return {skill["name"] for skill in get_available_skills()["vulnerabilities"]}


def test_every_vulnerability_skill_declares_its_phrasings() -> None:
    """A new skill without phrasings would be matched by its filename alone,
    which is how the false gap above got published."""
    missing = _vulnerability_skill_names() - set(_SKILL_PHRASINGS)

    assert not missing, f"add ledger phrasings for: {sorted(missing)}"


def test_declared_phrasings_name_real_skills() -> None:
    stale = set(_SKILL_PHRASINGS) - _vulnerability_skill_names()

    assert not stale, f"phrasings for skills that no longer exist: {sorted(stale)}"


def _delegating_graph(**overrides: Any) -> dict[str, Any]:
    base: dict[str, Any] = {
        "statuses": {"root": "completed", "agent-1": "completed"},
        "names": {"root": "Root Agent", "agent-1": "authz-tester"},
        "parent_of": {"agent-1": "root"},
        "metadata": {"agent-1": {"skills": ["idor"]}},
    }
    base.update(overrides)
    return base


def test_delegating_root_agent_is_not_a_coverage_gap() -> None:
    """The root delegates and reconciles; it is not a tester that went quiet.
    Flagging it would put the same false line in every clean report."""
    doc = _document(agent_graph=_delegating_graph())

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert silent == []


def test_a_subagent_that_records_nothing_is_still_a_gap() -> None:
    doc = _document(
        agent_graph=_delegating_graph(
            statuses={"root": "completed", "agent-1": "completed", "agent-2": "completed"},
            names={"root": "Root Agent", "agent-1": "authz-tester", "agent-2": "recon"},
            parent_of={"agent-1": "root", "agent-2": "root"},
        )
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["recon"]


def test_a_root_that_worked_alone_is_held_to_the_rule() -> None:
    """With no subagents there is nobody else the testing could have come
    from, so silence is a real gap."""
    doc = _document(
        entries=[],
        agent_graph={
            "statuses": {"root": "completed"},
            "names": {"root": "Root Agent"},
            "parent_of": {},
        },
    )

    silent = [gap for gap in doc["gaps"] if gap["kind"] == "agent_recorded_no_coverage"]
    assert [gap["agent_name"] for gap in silent] == ["Root Agent"]


def test_a_runtime_recorded_row_keeps_its_provenance() -> None:
    doc = _document(
        entries=[_entry(source="runtime", agent_name="system", outcome="needs_follow_up")]
    )

    assert doc["entries"][0]["source"] == "runtime"
    assert doc["entries"][0]["recorded_by"] == "system"


def _typed_hunter_graph(status: str = "crashed", **meta: Any) -> dict[str, Any]:
    return {
        "statuses": {"h1": status},
        "names": {"h1": "Deserialization hunter"},
        "metadata": {"h1": {"role": "hunter", "hunt_class": "rce", "skills": [], **meta}},
    }


def test_a_typed_hunter_with_no_hunt_report_leaves_its_class_unrecorded() -> None:
    assert unrecorded_hunt_classes([], _typed_hunter_graph()) == [
        {
            "vuln_class": "rce",
            "hunters": [
                {"agent_id": "h1", "agent_name": "Deserialization hunter", "status": "crashed"}
            ],
            "closed_rows": [],
        }
    ]
    assert unrecorded_hunt_classes([], _typed_hunter_graph(hunt_report={"open_items": []})) == []


def test_a_hunters_own_closure_does_not_record_its_class_without_a_hunt_report() -> None:
    own = _entry(entry_id="e1", risk_area="RCE", agent_id="h1", agent_name="Deserialization hunter")

    gaps = unrecorded_hunt_classes([own], _typed_hunter_graph())

    assert [gap["vuln_class"] for gap in gaps] == ["rce"]
    # The row stands as its partial account and is named, so the duplicate is seen coming.
    assert gaps[0]["closed_rows"] == [
        {
            "entry_id": "e1",
            "surface": "POST /api/orders/{id}",
            "outcome": "no_issue_found",
            "recorded_by": "Deserialization hunter",
        }
    ]


def test_an_open_row_must_name_the_class_as_whole_words() -> None:
    """The slug inside a longer word is not the class; substring matching accepted it."""
    inside_a_word = _entry(risk_area="exposed resources", outcome="needs_follow_up")
    assert unrecorded_hunt_classes([inside_a_word], _typed_hunter_graph()) != []

    named = _entry(risk_area="RCE", outcome="needs_follow_up")
    assert unrecorded_hunt_classes([named], _typed_hunter_graph()) == []


def _traversal_graph() -> dict[str, Any]:
    graph = _typed_hunter_graph()
    graph["metadata"]["h1"]["hunt_class"] = "path_traversal_lfi_rfi"
    return graph


@pytest.mark.parametrize(
    ("risk_area", "records"),
    [
        ("path_traversal_lfi_rfi", True),  # the raw slug, as the rejection hands it out
        ("Path Traversal LFI RFI", True),  # the same words, spaced
        ("Path Traversal", False),  # a partial overlap is a different, looser claim
        ("path traversal lfi", False),
        ("lfi rfi path traversal", False),  # the words out of order are not the slug
    ],
)
def test_a_multi_word_class_is_recorded_only_by_its_whole_slug(
    risk_area: str, records: bool
) -> None:
    row = _entry(risk_area=risk_area, outcome="needs_follow_up")

    assert (unrecorded_hunt_classes([row], _traversal_graph()) == []) is records


def test_one_open_row_naming_several_classes_records_each_of_them() -> None:
    graph = {
        "statuses": {"h1": "crashed", "h2": "stopped"},
        "names": {"h1": "Request forgery hunter", "h2": "Redirect hunter"},
        "metadata": {
            "h1": {"role": "hunter", "hunt_class": "ssrf", "skills": []},
            "h2": {"role": "hunter", "hunt_class": "open_redirect", "skills": []},
        },
    }
    assert [gap["vuln_class"] for gap in unrecorded_hunt_classes([], graph)] == [
        "open_redirect",
        "ssrf",
    ]

    row = _entry(risk_area="SSRF / open redirect", outcome="needs_follow_up")

    assert unrecorded_hunt_classes([row], graph) == []
