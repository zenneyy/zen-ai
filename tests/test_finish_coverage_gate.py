"""finish_scan confronts the root agent with the coverage the runtime can see."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any, cast
from unittest.mock import MagicMock

import pytest
from agents.tool_context import ToolContext

import zen.tools.threat_model.tools as tm
from zen.core.agents import AgentCoordinator
from zen.core.hooks import FINAL_STAGE_KEY, ReportUsageHooks
from zen.core.paths import runtime_state_dir
from zen.report.state import ReportState, set_global_report_state
from zen.tools.coverage.tools import (
    _record_impl,
    _update_impl,
    get_coverage_entries,
    hydrate_coverage_from_disk,
)
from zen.tools.finish import tool as finish_tool
from zen.tools.finish.tool import (
    COVERAGE_GATE_DISPOSAL_EXAMPLE,
    _coverage_summary,
    _do_finish,
    finish_scan,
)


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


_GRAPH = {
    "statuses": {"agent-1": "completed"},
    "names": {"agent-1": "injection-tester"},
    "metadata": {"agent-1": {"skills": ["sql_injection", "xss"]}},
}


@pytest.fixture(autouse=True)
def _empty_ledger(tmp_path: Path) -> None:
    hydrate_coverage_from_disk(tmp_path)


def _record(risk_area: str) -> None:
    _record_impl(
        surface="POST /api/orders/{id}",
        risk_area=risk_area,
        outcome="no_issue_found",
        evidence="Parameters fuzzed; no anomalies.",
        agent_id="agent-1",
        agent_name="injection-tester",
    )


def test_unrecorded_risk_class_is_reported_back_to_the_root_agent() -> None:
    _record("SQL injection")

    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 1
    assert len(summary["coverage_gaps"]) == 1
    assert "xss" in summary["coverage_gaps"][0]
    assert "unexamined" in summary["coverage_gap_warning"]


def test_fully_accounted_coverage_raises_no_gap_warning() -> None:
    _record("SQL injection")
    _record("cross-site scripting")

    summary = _coverage_summary(_GRAPH)

    assert "coverage_gaps" not in summary
    assert "coverage_gap_warning" not in summary


def test_an_empty_ledger_still_warns_first() -> None:
    summary = _coverage_summary(_GRAPH)

    assert summary["coverage_recorded"] == 0
    assert "No coverage was recorded" in summary["coverage_warning"]


# --- the coverage gate: evaluated before persistence, blocking on exact signals ----

_HUNTER = "hunter-1"
_HUNTER_NAME = "Reflected input hunter"
_RESERVE = "the sub-agent budget reserve was reached"
_OPEN_LEAD = "## Hypotheses\n- id: H1 | basis: assumed | state: open\n"
_DISPOSED_LEAD = "## Hypotheses\n- id: H1 | basis: assumed | state: open | disposition: deferred\n"


@pytest.fixture
def run(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[ReportState]:
    """One isolated run: its own run dir, coverage ledger, and empty threat-model store."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(tm, "_MODELS", {})
    state = ReportState(run_name="run-1")
    hydrate_coverage_from_disk(runtime_state_dir(state.get_run_dir()))
    set_global_report_state(state)
    try:
        yield state
    finally:
        set_global_report_state(None)


def _hunt_graph(
    *,
    status: str = "crashed",
    hunt_class: str | None = "xss",
    hunt_report: bool = False,
    skills: tuple[str, ...] = ("coordination/hunter_agent", "vulnerabilities/xss"),
    role: str = "hunter",
) -> dict[str, Any]:
    meta: dict[str, Any] = {"task": "hunt", "skills": list(skills), "role": role}
    if hunt_class is not None:
        meta["hunt_class"] = hunt_class
    if hunt_report:
        meta["hunt_report"] = {"impact_reached": None, "open_items": ["variant tree unfinished"]}
    return {
        "statuses": {"root": "running", _HUNTER: status},
        "names": {"root": "Root Agent", _HUNTER: _HUNTER_NAME},
        "parent_of": {"root": None, _HUNTER: "root"},
        "metadata": {"root": {"task": "", "skills": [], "role": "generic"}, _HUNTER: meta},
    }


def _finish(graph: dict[str, Any], *, wind_down: str | None = None) -> dict[str, Any]:
    return _do_finish(
        parent_id=None,
        executive_summary="x",
        methodology="x",
        technical_analysis="x",
        recommendations="x",
        agent_graph=graph,
        wind_down=wind_down,
    )


def _row(
    risk_area: str,
    *,
    outcome: str = "no_issue_found",
    evidence: str = "Reviewed; nothing anomalous.",
    agent_id: str = "root",
    agent_name: str = "Root Agent",
    approaches: list[str] | None = None,
) -> dict[str, Any]:
    return _record_impl(
        surface="GET /search",
        risk_area=risk_area,
        outcome=outcome,
        evidence=evidence,
        agent_id=agent_id,
        agent_name=agent_name,
        approaches_tried=approaches,
    )


def _persisted(state: ReportState) -> bool:
    return (state.get_run_dir() / "penetration_test_report.md").is_file()


def _published_coverage(state: ReportState) -> dict[str, Any]:
    path = state.get_run_dir() / "coverage.json"
    return cast("dict[str, Any]", json.loads(path.read_text(encoding="utf-8")))


def test_coverage_is_evaluated_before_the_run_is_marked_complete(
    run: ReportState, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []
    real = finish_tool._coverage_summary

    def _spy(graph: dict[str, Any]) -> dict[str, Any]:
        seen.append(run.run_record["status"])
        return real(graph)

    monkeypatch.setattr(finish_tool, "_coverage_summary", _spy)

    result = _finish(_hunt_graph(hunt_report=True))

    assert result["success"] is True
    assert seen == ["running"]
    assert run.run_record["status"] == "completed"


def test_an_unrecorded_class_blocks_finish_names_it_and_persists_nothing(
    run: ReportState,
) -> None:
    result = _finish(_hunt_graph())

    assert result["success"] is False
    assert result["scan_completed"] is False
    assert result["unrecorded_classes"] == ["xss"]
    assert "Coverage gate" in result["error"]
    assert _HUNTER_NAME in result["error"]
    assert "crashed" in result["error"]
    # The rejection teaches the exact disposal grammar, from the gate's single source.
    assert COVERAGE_GATE_DISPOSAL_EXAMPLE in result["error"]
    # Nothing terminal happened: no report, no completion, no end time.
    assert not _persisted(run)
    assert run.run_record["status"] == "running"
    assert run.end_time is None
    assert run.scan_results is None


def test_a_blocked_finish_changes_nothing_and_is_repeatable(run: ReportState) -> None:
    graph = _hunt_graph()

    assert _finish(graph) == _finish(graph)
    assert get_coverage_entries() == []
    assert not (run.get_run_dir() / "run.json").exists()


def test_recording_the_class_as_open_lets_the_scan_finish_and_publishes_it(
    run: ReportState,
) -> None:
    graph = _hunt_graph()
    assert _finish(graph)["success"] is False

    _row("xss", outcome="needs_follow_up", evidence="The assigned hunter crashed before testing.")
    result = _finish(graph)

    assert result["success"] is True
    assert result["scan_completed"] is True
    assert run.run_record["status"] == "completed"
    assert _persisted(run)
    published = _published_coverage(run)
    assert [gap["kind"] for gap in published["gaps"]] == ["needs_follow_up"]
    assert published["entries"][0]["outcome_label"] == "Requires further review"


@pytest.mark.parametrize("outcome", ["no_issue_found", "ruled_out", "not_applicable"])
def test_a_closure_written_on_the_dead_hunters_behalf_does_not_open_the_gate(
    run: ReportState, outcome: str
) -> None:
    recorded = _row("xss", outcome=outcome, evidence="Looked fine.", approaches=["read it"])
    assert recorded["success"] is True

    result = _finish(_hunt_graph())

    assert result["success"] is False
    assert result["unrecorded_classes"] == ["xss"]
    assert not _persisted(run)


@pytest.mark.usefixtures("run")
def test_a_filed_hunt_report_records_the_class() -> None:
    assert _finish(_hunt_graph(status="completed", hunt_report=True))["success"] is True


@pytest.mark.parametrize("partial", ["coverage_entry", "filed_report"])
def test_rows_and_reports_recorded_before_dying_do_not_record_the_class(
    run: ReportState, partial: str
) -> None:
    if partial == "coverage_entry":
        _row("reflected markup in the search box", agent_id=_HUNTER, agent_name=_HUNTER_NAME)
    else:
        run.add_vulnerability_report(
            title="Reflected markup", severity="low", agent_id=_HUNTER, agent_name=_HUNTER_NAME
        )

    result = _finish(_hunt_graph())

    # No hunt report was filed, so the class is still owed...
    assert result["success"] is False
    assert result["unrecorded_classes"] == ["xss"]
    assert not _persisted(run)
    # ...and what the hunter did record stands untouched as its partial account.
    assert len(get_coverage_entries()) == (1 if partial == "coverage_entry" else 0)
    assert len(run.vulnerability_reports) == (1 if partial == "filed_report" else 0)


@pytest.mark.usefixtures("run")
def test_the_dead_hunters_own_open_row_records_the_class() -> None:
    _row(
        "xss",
        outcome="needs_follow_up",
        evidence="Could not reach the sink before the session expired.",
        agent_id=_HUNTER,
        agent_name=_HUNTER_NAME,
    )

    assert _finish(_hunt_graph())["success"] is True


@pytest.mark.usefixtures("run")
def test_a_second_hunter_of_the_same_class_records_it() -> None:
    graph = _hunt_graph()
    graph["statuses"]["hunter-2"] = "completed"
    graph["names"]["hunter-2"] = "Replacement hunter"
    graph["parent_of"]["hunter-2"] = "root"
    graph["metadata"]["hunter-2"] = {
        "role": "hunter",
        "hunt_class": "xss",
        "skills": [],
        "hunt_report": {"impact_reached": None},
    }

    assert _finish(graph)["success"] is True


@pytest.mark.parametrize(
    "graph",
    [
        # Skills beyond the typed class are background: nothing is owed for them.
        _hunt_graph(
            hunt_report=True,
            skills=(
                "vulnerabilities/xss",
                "vulnerabilities/xss_advanced_deep",
                "vulnerabilities/ssrf",
            ),
        ),
        # No typed class: there is no structural assignment to hold it to.
        _hunt_graph(hunt_class=None),
        # A typed class on a non-hunter role is not an assignment either.
        _hunt_graph(role="recon"),
    ],
    ids=["background-skills", "untyped-hunter", "non-hunter-role"],
)
@pytest.mark.usefixtures("run")
def test_background_skills_and_untyped_agents_are_never_owed(graph: dict[str, Any]) -> None:
    result = _finish(graph)

    assert result["success"] is True
    assert "unrecorded_classes" not in result


def test_recorded_open_rows_never_block_and_are_published(run: ReportState) -> None:
    _row(
        "stored markup in comments",
        outcome="needs_follow_up",
        evidence="No second account to view the stored value.",
        agent_id=_HUNTER,
        agent_name=_HUNTER_NAME,
    )

    result = _finish(_hunt_graph(status="completed", hunt_report=True))

    assert result["success"] is True
    assert result["unresolved_surfaces"] == [
        {"surface": "GET /search", "risk_area": "stored markup in comments"}
    ]
    assert [gap["kind"] for gap in _published_coverage(run)["gaps"]] == ["needs_follow_up"]


@pytest.mark.usefixtures("run")
def test_no_typed_assignment_keeps_todays_warning_only() -> None:
    result = _finish({})

    assert result["success"] is True
    assert "No coverage was recorded" in result["coverage_warning"]


@pytest.mark.parametrize(
    ("target", "graph"),
    [
        ("zen.report.coverage.unrecorded_hunt_classes", _hunt_graph()),
        ("zen.tools.finish.tool._coverage_summary", _hunt_graph(hunt_report=True)),
    ],
    ids=["gate-evaluator", "advisory-summary"],
)
def test_an_evaluator_error_never_blocks_or_unpersists(
    run: ReportState, monkeypatch: pytest.MonkeyPatch, target: str, graph: dict[str, Any]
) -> None:
    def _boom(*_args: Any, **_kwargs: Any) -> Any:
        raise RuntimeError("evaluator bug")

    monkeypatch.setattr(target, _boom)

    result = _finish(graph)

    assert result["success"] is True
    assert result["scan_completed"] is True
    assert run.run_record["status"] == "completed"


def test_forced_wind_down_records_the_class_itself_and_still_finalizes(
    run: ReportState,
) -> None:
    graph = _hunt_graph(status="stopped")

    result = _finish(graph, wind_down=_RESERVE)

    assert result["success"] is True
    assert result["system_recorded_unexamined"] == ["xss"]
    assert run.run_record["status"] == "completed"
    assert _persisted(run)
    rows = [row for row in get_coverage_entries() if row.get("agent_name") == "system"]
    assert len(rows) == 1
    assert rows[0]["risk_area"] == "xss"
    assert rows[0]["outcome"] == "needs_follow_up"
    assert rows[0]["source"] == "runtime"
    assert _HUNTER_NAME in rows[0]["evidence"]
    published = _published_coverage(run)["entries"]
    assert [(e["recorded_by"], e["source"]) for e in published] == [("system", "runtime")]

    # Retrying or resuming finds the class recorded and writes nothing more.
    assert _finish(graph, wind_down=_RESERVE)["success"] is True
    assert len([r for r in get_coverage_entries() if r.get("agent_name") == "system"]) == 1


def test_a_wind_down_records_the_lead_and_the_class_and_finalizes(run: ReportState) -> None:
    tm._MODELS["target"] = {"content": _OPEN_LEAD}

    result = _finish(_hunt_graph(), wind_down=_RESERVE)

    assert result["success"] is True
    assert result["system_recorded_undisposed"] == ["H1"]
    assert result["system_recorded_unexamined"] == ["xss"]
    assert _persisted(run)
    assert [row.get("source") for row in get_coverage_entries()] == ["runtime", "runtime"]


def test_a_lead_and_a_class_are_named_in_one_rejection(run: ReportState) -> None:
    tm._MODELS["target"] = {"content": _OPEN_LEAD}

    result = _finish(_hunt_graph())

    assert result["success"] is False
    assert result["undisposed_hypotheses"] == ["H1"]
    assert "Closure gate" in result["error"]
    assert result["unrecorded_classes"] == ["xss"]
    assert "xss" in result["coverage_error"]
    assert not _persisted(run)


def test_a_duplicate_of_an_earlier_closure_is_named_and_can_be_reopened(
    run: ReportState,
) -> None:
    closed = _row("xss", outcome="no_issue_found", evidence="Looked fine.")

    blocked = _finish(_hunt_graph())

    # The rejection names the row that already holds that surface and class...
    assert str(closed["entry_id"]) in blocked["error"]
    assert "update_coverage" in blocked["error"]
    # ...because recording the disposal example over it is refused as a duplicate.
    duplicate = _row("xss", outcome="needs_follow_up", evidence="Hunter crashed before testing.")
    assert duplicate["success"] is False
    assert duplicate["existing_entry_id"] == closed["entry_id"]
    assert duplicate["existing_outcome"] == "no_issue_found"

    _update_impl(
        entry_id=str(closed["entry_id"]),
        outcome="needs_follow_up",
        evidence="Reopened: the assigned hunter crashed before testing this.",
        agent_id="root",
        agent_name="Root Agent",
    )

    assert _finish(_hunt_graph())["success"] is True
    entry = _published_coverage(run)["entries"][0]
    assert entry["outcome"] == "needs_follow_up"
    assert entry["previous_outcomes"] == ["no_issue_found"]


def test_an_open_row_on_a_more_specific_surface_leaves_a_real_review_alone(
    run: ReportState,
) -> None:
    _row("xss", agent_id="gen-1", agent_name="Generalist")
    _record_impl(
        surface="GET /search (variant space assigned to the hunter)",
        risk_area="xss",
        outcome="needs_follow_up",
        evidence="The assigned hunter crashed; only the basic case was reviewed elsewhere.",
        agent_id="root",
        agent_name="Root Agent",
    )

    assert _finish(_hunt_graph())["success"] is True
    outcomes = sorted(entry["outcome"] for entry in _published_coverage(run)["entries"])
    assert outcomes == ["needs_follow_up", "no_issue_found"]


def test_a_runtime_row_revised_by_an_agent_stops_claiming_runtime_provenance(
    run: ReportState,
) -> None:
    graph = _hunt_graph(status="stopped")
    assert _finish(graph, wind_down=_RESERVE)["success"] is True
    row = next(r for r in get_coverage_entries() if r.get("source") == "runtime")

    _update_impl(
        entry_id=str(row["entry_id"]),
        outcome="no_issue_found",
        evidence="Re-tested by hand; output is encoded.",
        agent_id="rev-1",
        agent_name="Reviewer",
    )

    revised = get_coverage_entries()[0]
    assert "source" not in revised
    assert revised["history"][0]["source"] == "runtime"
    run.save_run_data()
    assert _published_coverage(run)["entries"][0]["source"] == "agent_reported"
    # A closure laid over the runtime's open row is not a record of the class.
    assert _finish(graph)["unrecorded_classes"] == ["xss"]


@pytest.mark.usefixtures("run")
def test_a_wind_down_mid_disposal_records_only_what_is_still_unrecorded() -> None:
    graph = _hunt_graph()
    graph["statuses"]["hunter-2"] = "stopped"
    graph["names"]["hunter-2"] = "Request forgery hunter"
    graph["parent_of"]["hunter-2"] = "root"
    graph["metadata"]["hunter-2"] = {"role": "hunter", "hunt_class": "ssrf", "skills": []}
    assert _finish(graph)["unrecorded_classes"] == ["ssrf", "xss"]

    # Root disposes of one class, one call per turn, before the runtime winds down.
    _row("xss", outcome="needs_follow_up", evidence="The assigned hunter crashed.")
    result = _finish(graph, wind_down=_RESERVE)

    assert result["success"] is True
    assert result["system_recorded_unexamined"] == ["ssrf"]
    recorded_by = {row["risk_area"]: row.get("agent_name") for row in get_coverage_entries()}
    assert recorded_by == {"xss": "Root Agent", "ssrf": "system"}


# --- the closure gate under a forced wind-down --------------------------------------

_RECORDED_AS = {
    "open": "`open`",
    "blocked": "`blocked`",
    "testing": "`testing`",
    "refuted": "`refuted` with no stated grounds",
}


def _lead_model(state: str, extra: str = "") -> dict[str, str]:
    more = f" | {extra}" if extra else ""
    return {"content": f"## Hypotheses\n- id: H1 | basis: assumed | state: {state}{more}\n"}


def _system_lead_rows() -> list[dict[str, Any]]:
    return [
        row
        for row in get_coverage_entries()
        if row.get("agent_name") == "system" and row["surface"].startswith("Threat-model lead")
    ]


@pytest.mark.parametrize("state", list(_RECORDED_AS))
def test_a_wind_down_records_an_undisposed_lead_itself_and_still_finalizes(
    run: ReportState, state: str
) -> None:
    tm._MODELS["target"] = _lead_model(state, "vuln_class: xss")
    before = dict(tm._MODELS["target"])

    result = _finish({}, wind_down=_RESERVE)

    assert result["success"] is True
    assert result["system_recorded_undisposed"] == ["H1"]
    assert _persisted(run)
    rows = _system_lead_rows()
    assert len(rows) == 1
    assert rows[0]["outcome"] == "needs_follow_up"
    assert rows[0]["source"] == "runtime"
    assert "H1" in rows[0]["surface"]
    evidence = rows[0]["evidence"]
    # The row says what the runtime knows: the recorded state, that no disposition
    # was recorded, and that the model was not re-saved before the forced finish...
    assert f"as {_RECORDED_AS[state]}, with no disposition" in evidence
    assert "was not re-saved before the scan finished" in evidence
    # ...and makes no claim about what was or was not tested.
    for claim in ("prosecuted", "tested", "examined", "clean"):
        assert claim not in evidence
    # The runtime publishes the lead; it never rewrites the lead's own record.
    assert tm._MODELS["target"] == before


def test_outside_a_wind_down_a_testing_lead_blocks_and_nothing_is_written(
    run: ReportState,
) -> None:
    tm._MODELS["target"] = _lead_model("testing")

    result = _finish({})

    assert result["success"] is False
    assert result["undisposed_reasons"] == {"H1": "testing"}
    assert get_coverage_entries() == []
    assert not _persisted(run)
    assert run.run_record["status"] == "running"


@pytest.mark.usefixtures("run")
def test_retrying_a_wind_down_finish_records_each_lead_once() -> None:
    tm._MODELS["target"] = _lead_model("testing")

    first = _finish({}, wind_down=_RESERVE)
    second = _finish({}, wind_down=_RESERVE)

    assert first["system_recorded_undisposed"] == ["H1"]
    assert second["system_recorded_undisposed"] == ["H1"]
    assert len(_system_lead_rows()) == 1


@pytest.mark.usefixtures("run")
def test_a_runtime_lead_row_never_records_a_hunt_class() -> None:
    """The lead row names a lead, not a class: the coverage gate's accounting of an
    assigned class is untouched by it."""
    recorded = finish_tool._record_undisposed_leads(
        [{"id": "H1", "why": "testing", "vuln_class": "xss"}], _RESERVE
    )
    assert recorded == ["H1"]

    assert _finish(_hunt_graph())["unrecorded_classes"] == ["xss"]


# --- through the tool: hypotheses x coverage x mode, and the wind-down signals ------


async def _graph_run(coverage: str) -> AgentCoordinator:
    coordinator = AgentCoordinator()
    await coordinator.register("root", "Root Agent", parent_id=None)
    await coordinator.register(
        _HUNTER, _HUNTER_NAME, parent_id="root", skills=["vulnerabilities/xss"], role="hunter"
    )
    await coordinator.update_metadata(_HUNTER, hunt_class="xss")
    if coverage == "unrecorded":
        await coordinator.set_status(_HUNTER, "crashed")
        return coordinator
    await coordinator.update_metadata(_HUNTER, hunt_report={"impact_reached": None})
    await coordinator.set_status(_HUNTER, "completed")
    _row(
        "cross-site scripting",
        outcome="needs_follow_up" if coverage == "needs_follow_up" else "no_issue_found",
        evidence="No second account to compare.",
        agent_id=_HUNTER,
        agent_name=_HUNTER_NAME,
    )
    return coordinator


async def _call_finish(
    coordinator: AgentCoordinator, *, report: str = "x", **context: Any
) -> dict[str, Any]:
    ctx = ToolContext(
        context={"coordinator": coordinator, "agent_id": "root", "parent_id": None, **context},
        tool_name="finish_scan",
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    fields = ("executive_summary", "methodology", "technical_analysis", "recommendations")
    raw: str = await finish_scan.on_invoke_tool(ctx, json.dumps(dict.fromkeys(fields, report)))
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.parametrize("interactive", [True, False], ids=["interactive", "autonomous"])
@pytest.mark.parametrize("coverage", ["clean", "needs_follow_up", "unrecorded"])
@pytest.mark.parametrize("hypotheses", ["disposed", "undisposed"])
async def test_finish_is_blocked_exactly_when_a_lead_or_a_class_is_unaccounted(
    run: ReportState, hypotheses: str, coverage: str, interactive: bool
) -> None:
    lead = _DISPOSED_LEAD if hypotheses == "disposed" else _OPEN_LEAD
    tm._MODELS["target"] = {"content": lead}
    coordinator = await _graph_run(coverage)

    result = await _call_finish(coordinator, interactive=interactive)

    blocked = hypotheses == "undisposed" or coverage == "unrecorded"
    assert result["success"] is (not blocked)
    assert result["scan_completed"] is (not blocked)
    assert ("undisposed_hypotheses" in result) is (hypotheses == "undisposed")
    assert ("unrecorded_classes" in result) is (coverage == "unrecorded")
    assert _persisted(run) is (not blocked)
    assert run.run_record["status"] == ("running" if blocked else "completed")
    assert coordinator.statuses["root"] == ("running" if blocked else "completed")


async def test_the_reserve_stop_is_a_forced_wind_down(run: ReportState) -> None:
    coordinator = await _graph_run("unrecorded")
    await coordinator.claim_reserve_notification()

    result = await _call_finish(coordinator, interactive=False)

    assert result["success"] is True
    assert result["system_recorded_unexamined"] == ["xss"]
    assert _persisted(run)
    assert coordinator.statuses["root"] == "completed"


@pytest.mark.parametrize(("interactive", "finalized"), [(False, True), (True, False)])
async def test_the_final_warning_stage_is_a_wind_down_only_without_a_user(
    run: ReportState, interactive: bool, finalized: bool
) -> None:
    coordinator = await _graph_run("unrecorded")

    result = await _call_finish(
        coordinator, interactive=interactive, **{FINAL_STAGE_KEY: "turn budget"}
    )

    assert result["success"] is finalized
    assert _persisted(run) is finalized


async def test_a_finish_one_call_later_in_the_final_band_still_winds_down(
    run: ReportState,
) -> None:
    """The key is recomputed on every model call, so a finish rejected for another
    reason is not blocked afresh on the next call."""
    hooks = ReportUsageHooks(model="test-model", max_turns=100)
    coordinator = await _graph_run("unrecorded")
    context: dict[str, Any] = {"interactive": False}
    wrapper = MagicMock()
    wrapper.context = context
    tm._MODELS["target"] = {"content": _OPEN_LEAD}

    wrapper.usage.requests = 94  # this model call is turn 95 of 100
    await hooks.on_llm_start(wrapper, MagicMock(), None, [])
    first = await _call_finish(coordinator, report=" ", **context)
    assert first["error"] == "Validation failed"  # rejected before any gate ran
    assert not _persisted(run)

    wrapper.usage.requests = 95  # the next call, turn 96
    await hooks.on_llm_start(wrapper, MagicMock(), None, [])
    second = await _call_finish(coordinator, **context)
    assert second["success"] is True
    assert second["system_recorded_unexamined"] == ["xss"]
    assert second["system_recorded_undisposed"] == ["H1"]
    assert _persisted(run)
