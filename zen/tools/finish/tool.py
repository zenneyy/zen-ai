"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from zen.core.agents import coordinator_from_context
from zen.tools.threat_model.schema import (
    DEFERRAL_LINE_EXAMPLE,
    DISPOSITION_CONVENTION,
    DISPOSITION_LINE_EXAMPLE,
    REFUTATION_CONVENTION,
    REFUTATION_LINE_EXAMPLE,
    parse_deferrals,
    parse_hypotheses,
    refutation_problem,
)


if TYPE_CHECKING:
    from collections.abc import Iterable

    from zen.core.agents import AgentCoordinator
    from zen.tools.threat_model.schema import Hypothesis


logger = logging.getLogger(__name__)


# Hypothesis states that leave a lead unresolved at the finish boundary. A
# hypothesis in one of these must carry a recorded disposition before the scan can
# finish. ``testing`` is a valid state while the scan runs — the schema accepts it
# and nothing checks it mid-run — but once the scan ends nothing is still testing
# the lead, so here, and only here, it is read like ``open``. ``confirmed`` is
# terminal; ``refuted`` is terminal when it states its grounds.
_OPEN_HYPOTHESIS_STATES = frozenset({"open", "blocked", "testing"})

# Why a ``refuted`` lead is listed: the label is there, the grounds are not.
_REFUTED_WITHOUT_GROUNDS = "refuted without grounds"

# The leads the runtime publishes itself in a forced wind-down, by the reason
# each is undisposed. There a rejection can cost the scan its report. What the
# runtime writes is the state the model records and the fact that no disposition
# was recorded — it knows nothing about what was tested, and says nothing about it.
_RUNTIME_RECORDED_REASONS = frozenset({*_OPEN_HYPOTHESIS_STATES, _REFUTED_WITHOUT_GROUNDS})

_LEAD_RISK_AREA = "hypothesis with no recorded disposition"


# ── coverage gate: its teaching text, defined once ───────────────────────────
#
# The ``finish_scan`` description, the generated root CONTRACT, and the gate's own
# rejection all read these constants, so the text that teaches and the gate that
# enforces cannot drift.

COVERAGE_GATE_DISPOSAL_EXAMPLE = (
    'record_coverage(surface="<the surface that hunter was assigned>", '
    'risk_area="<vuln_class>", outcome="needs_follow_up", '
    'evidence="<why it was not examined>")'
)
"""The disposal grammar, shown verbatim wherever the coverage gate is taught."""

COVERAGE_GATE_DESCRIPTION = (
    "Every vulnerability class you assigned to a hunter through a typed `hunt_task` must have "
    "an explicit record before the scan finishes: the hunt report of a hunter assigned that "
    "class, or an open coverage entry that names the class. A hunter that crashed, stalled, or "
    "was stopped before `agent_finish` filed no hunt report; the rows it recorded and the "
    "reports it filed on the way stand as a partial account and do not record the class. "
    "Either have the class examined — dispatch a hunter for it again — or record it as open: "
    "outcome `needs_follow_up`, the class slug in `risk_area`, the reason in `evidence`. This "
    "gate asks for a record, never for a closure: `needs_follow_up` is a legitimate final "
    "outcome, and recording an unexamined class as `no_issue_found`, `ruled_out`, or "
    "`not_applicable` does not satisfy it. If `record_coverage` refuses the open row as a "
    "duplicate, do not overwrite another agent's real review: record it under a more specific "
    "surface, and use `update_coverage` only to reopen a closure that was itself written for "
    "the unexamined assignment. When no user is attached and the runtime tells you to finish "
    "immediately, call `finish_scan` without recording the rest: the runtime records what is "
    "still unrecorded, as unexamined, under its own name."
)
"""One class-agnostic statement of the coverage gate."""

_COVERAGE_GATE_MARKER = "{coverage_gate}"
_COVERAGE_GATE_TEACHING = (
    f"{COVERAGE_GATE_DESCRIPTION} Record an open class with `{COVERAGE_GATE_DISPOSAL_EXAMPLE}`."
)
_SYSTEM_RECORDER = "system"


# ── closure gate: its teaching text, defined once ────────────────────────────
#
# The ``finish_scan`` description, the generated root CONTRACT and the gate's own
# rejection read the same constants: the disposition and refutation conventions
# from the hypothesis schema, and this note on where a disposal is written.

CLOSURE_GATE_DISPOSAL_NOTE = (
    "Dispositions and refutation grounds are read from the saved model only: change them by "
    "re-saving it with `save_threat_model` — an amendment does not dispose a lead. When no "
    "user is attached and the runtime tells you to finish immediately, call `finish_scan` "
    "without re-saving: the runtime publishes, under its own name, the state the model records "
    "for each lead that still has no disposition. It changes no lead and marks none refuted."
)
"""Where a disposal is written, and what the runtime does in a forced wind-down."""

_CLOSURE_GATE_MARKER = "{closure_gate}"
_CLOSURE_GATE_TEACHING = (
    f"{DISPOSITION_CONVENTION} An inline disposition reads `{DISPOSITION_LINE_EXAMPLE}`; a "
    f"deferral record under a 'Deferred Hypotheses' section reads `{DEFERRAL_LINE_EXAMPLE}`. "
    f"{REFUTATION_CONVENTION} For example: `{REFUTATION_LINE_EXAMPLE}`. "
    f"{CLOSURE_GATE_DISPOSAL_NOTE}"
)


def _undisposed_reason(hypothesis: Hypothesis) -> str | None:
    """Why a lead is unresolved at the finish boundary, before dispositions are read.

    ``open``, ``blocked`` and ``testing`` are unresolved states; ``testing`` only
    counts here, at the end of the scan. A ``refuted`` hypothesis that does not
    state its grounds is a label rather than a resolution, by the rule the save
    gate enforces — read here too so a lead that reached the store without passing
    that gate (saved before the rule existed, replayed from the event log, hydrated
    from the mirror) is named instead of waved through.
    """
    if hypothesis.state in _OPEN_HYPOTHESIS_STATES:
        return str(hypothesis.state)
    if refutation_problem(hypothesis) is not None:
        return _REFUTED_WITHOUT_GROUNDS
    return None


def _undisposed_leads(
    hypotheses: Iterable[Hypothesis], deferred: set[str]
) -> list[dict[str, str]]:
    """Unresolved leads with no recorded disposition, each with why it is listed."""
    return [
        {"id": hypothesis.id, "why": why, "vuln_class": hypothesis.vuln_class}
        for hypothesis in hypotheses
        if (why := _undisposed_reason(hypothesis)) is not None
        and hypothesis.disposition is None
        and hypothesis.id not in deferred
    ]


def _undisposed_leads_in(content: str) -> list[dict[str, str]]:
    """The closure gate over one model's document."""
    hypotheses, _ = parse_hypotheses(content)
    deferrals, _ = parse_deferrals(content)
    return _undisposed_leads(hypotheses, {deferral.hypothesis_id for deferral in deferrals})


def _undisposed_open_hypotheses(content: str) -> list[str]:
    """Ids of the leads in one model the closure gate still holds open.

    A hypothesis counts as disposed when any one of these holds: it is
    ``confirmed``, or ``refuted`` with its grounds stated; it carries an inline
    ``disposition`` on its own hypothesis line; or a ``## Deferred Hypotheses``
    record names its id. Anything left open, blocked or testing — or refuted with
    no grounds — with none of these is an undisposed lead, returned by id.
    """
    return [lead["id"] for lead in _undisposed_leads_in(content)]


def _undisposed_from_ledger(ledger: object) -> list[dict[str, str]]:
    """The closure gate as a query over the ledger's typed hypotheses.

    For each saved document, the hypotheses are read as typed
    :class:`~zen.tools.threat_model.schema.Hypothesis` rows (their ``state`` and
    inline ``disposition`` are object fields, not re-parsed prose); the dedicated
    ``## Deferred Hypotheses`` dispositions — the other disposition channel — are
    read from the document view the ledger projects. Behavior-equivalent to the
    prose path: the typed rows were parsed from the same body, and the deferral
    grammar is the same.
    """
    leads: list[dict[str, str]] = []
    for identity in ledger.model_identities():  # type: ignore[attr-defined]
        hypotheses = ledger.get_hypotheses(identity)  # type: ignore[attr-defined]
        view = ledger.get_model_view(identity)  # type: ignore[attr-defined]
        deferrals, _ = parse_deferrals(str(view.get("content", "")) if view else "")
        leads.extend(_undisposed_leads(hypotheses, {d.hypothesis_id for d in deferrals}))
    return leads


def _undisposed_leads_across_run() -> list[dict[str, str]]:
    """Every undisposed lead across the threat models this run holds, each once.

    Queries the run-scoped research ledger's typed hypotheses when one is
    installed, and falls back to parsing the threat-model dict store otherwise.
    With no model saved there are no hypotheses and the closure gate is a no-op.
    """
    from zen.tools.ledger.runtime import get_ledger

    ledger = get_ledger()
    if ledger is not None and ledger.has_models():
        found = _undisposed_from_ledger(ledger)
    else:
        from zen.tools.threat_model.tools import _MODELS, _store_lock

        with _store_lock:
            contents = [
                str(model.get("content", ""))
                for model in _MODELS.values()
                if isinstance(model, dict)
            ]
        found = [lead for content in contents for lead in _undisposed_leads_in(content)]
    seen: set[str] = set()
    ordered: list[dict[str, str]] = []
    for lead in found:
        if lead["id"] not in seen:
            seen.add(lead["id"])
            ordered.append(lead)
    return ordered


def _undisposed_hypotheses_across_run(leads: list[dict[str, str]] | None = None) -> list[str]:
    """Undisposed hypothesis ids across every threat model this run holds.

    Given the leads one evaluation already found, names those; otherwise evaluates.
    """
    found = _undisposed_leads_across_run() if leads is None else leads
    return [lead["id"] for lead in found]


def _split_for_wind_down(
    leads: list[dict[str, str]], wind_down: str | None
) -> tuple[list[dict[str, str]], list[dict[str, str]]]:
    """Split undisposed leads into those that block and those the runtime records."""
    if not wind_down:
        return leads, []
    runtime = [lead for lead in leads if lead["why"] in _RUNTIME_RECORDED_REASONS]
    blocking = [lead for lead in leads if lead["why"] not in _RUNTIME_RECORDED_REASONS]
    return blocking, runtime


def _closure_rejection(leads: list[dict[str, str]]) -> dict[str, Any]:
    """The closure gate's rejection: every undisposed lead at once, and how to dispose each."""
    named = ", ".join(f"{lead['id']} ({lead['why']})" for lead in leads)
    return {
        "success": False,
        "scan_completed": False,
        "error": (
            "Closure gate: the scan cannot finish while these threat-model hypotheses are "
            "undisposed — open, blocked or testing with no recorded disposition, or refuted "
            f"with no stated grounds: {named}. {_CLOSURE_GATE_TEACHING} A lead is disposed of, "
            "never dropped silently."
        ),
        "undisposed_hypotheses": [lead["id"] for lead in leads],
        "undisposed_reasons": {lead["id"]: lead["why"] for lead in leads},
    }


def _record_undisposed_leads(leads: list[dict[str, str]], wind_down: str | None) -> list[str]:
    """Publish each lead the scan is winding down on, attributed to the runtime.

    Only in a forced wind-down. The runtime writes one open coverage entry per
    lead saying what it knows and nothing else: the state the saved model records
    for the lead, that no disposition was recorded, and that the model was not
    re-saved before the scan finished. Leads are labelled at the end of a scan, so
    a lead still ``open`` in the model may well have been tested, reported or
    ruled out — the row makes no claim either way. It never touches the model.
    Best-effort: a row that cannot be written is logged and the scan still
    finalizes; a row already there from an earlier attempt counts as recorded.
    """
    recorded: list[str] = []
    if not leads or not wind_down:
        return recorded
    try:
        from zen.tools.coverage.tools import _record_impl

        for lead in leads:
            lead_id = lead["id"]
            named_class = f" (class: {lead['vuln_class']})" if lead["vuln_class"] else ""
            state = (
                "`refuted` with no stated grounds"
                if lead["why"] == _REFUTED_WITHOUT_GROUNDS
                else f"`{lead['why']}`"
            )
            outcome = _record_impl(
                surface=f"Threat-model lead {lead_id}",
                risk_area=_LEAD_RISK_AREA,
                outcome="needs_follow_up",
                evidence=(
                    f"Recorded by the runtime at finish because {wind_down}: the saved threat "
                    f"model records hypothesis {lead_id}{named_class} as {state}, with no "
                    "disposition, and the model was not re-saved before the scan finished. "
                    "This reports the model's record only: the runtime did not assess the lead."
                ),
                agent_id=None,
                agent_name=_SYSTEM_RECORDER,
                source="runtime",
            )
            if outcome.get("success") or outcome.get("existing_entry_id"):
                recorded.append(lead_id)
            else:
                logger.warning(
                    "undisposed lead %s was not recorded at finish: %s",
                    lead_id,
                    outcome.get("error"),
                )
    except Exception:
        logger.exception("could not record undisposed leads at finish; finalizing anyway")
    return recorded


def _unrecorded_classes(agent_graph: dict[str, Any]) -> list[dict[str, Any]]:
    """The coverage gate's evaluation: typed hunt classes left with no record.

    Read-only, so a rejected finish changes nothing and can be retried or resumed
    freely. A failure in here must never decide whether a scan can finish: it is
    logged and treated as nothing to block on, and the advisory summary still
    reports what it can see. A real gap never takes that path — it is a value
    this function returns, not an exception it raises.
    """
    try:
        from zen.report.coverage import unrecorded_hunt_classes
        from zen.tools.coverage.tools import get_coverage_entries

        unrecorded = unrecorded_hunt_classes(get_coverage_entries(), agent_graph)
    except Exception:
        logger.exception("coverage gate evaluation failed; finishing on the advisory summary")
        return []
    return unrecorded


def _hunters_label(gap: dict[str, Any]) -> str:
    return ", ".join(f"{hunter['agent_name']} [{hunter['status']}]" for hunter in gap["hunters"])


def _closed_rows_label(gap: dict[str, Any]) -> str:
    """Rows that already name the class but closed it, so the duplicate is seen coming."""
    rows = gap.get("closed_rows") or []
    if not rows:
        return ""
    listed = ", ".join(
        f"{row['entry_id']} '{row['surface']}' as {row['outcome']} by {row['recorded_by']}"
        for row in rows
    )
    return f"; already recorded but closed: {listed}"


def _coverage_gate_error(unrecorded: list[dict[str, Any]]) -> str:
    """The rejection text: every unrecorded class at once, with how to record it."""
    named = "; ".join(
        f"{gap['vuln_class']} (assigned to {_hunters_label(gap)}{_closed_rows_label(gap)})"
        for gap in unrecorded
    )
    return (
        "Coverage gate: the scan cannot finish while these assigned vulnerability classes have "
        f"no record: {named}. {_COVERAGE_GATE_TEACHING} A class is accounted for, never "
        "shipped silently."
    )


def _coverage_rejection(blocking: list[dict[str, Any]], *, error_key: str) -> dict[str, Any]:
    """The coverage half of a rejection; empty when no class blocks."""
    if not blocking:
        return {}
    return {
        error_key: _coverage_gate_error(blocking),
        "unrecorded_classes": [gap["vuln_class"] for gap in blocking],
    }


def _record_unexamined(unrecorded: list[dict[str, Any]], wind_down: str | None) -> list[str]:
    """Record each unrecorded class as open, attributed to the runtime.

    Only in a forced wind-down, where a rejection would spend the turns the final
    report needs. The runtime writes the row the root agent would have been asked
    for — open, never closed — so the class is published as unexamined under the
    runtime's own name rather than shipping silently or costing the scan its
    report. Best-effort: a row that cannot be written is logged and the scan
    still finalizes.
    """
    recorded: list[str] = []
    if not unrecorded or not wind_down:
        return recorded
    try:
        from zen.tools.coverage.tools import _record_impl

        for gap in unrecorded:
            vuln_class = str(gap["vuln_class"])
            holders = ", ".join(str(hunter["agent_name"]) for hunter in gap["hunters"])
            outcome = _record_impl(
                surface=f"Assignment of {holders}",
                risk_area=vuln_class,
                outcome="needs_follow_up",
                evidence=(
                    f"Recorded by the runtime at finish because {wind_down}: the hunter "
                    f"assigned this class ({_hunters_label(gap)}) ended without filing its "
                    "hunt report. Any coverage entries or reports it recorded before stopping "
                    "stand as a partial account; the rest of the assignment is unexamined — "
                    "not assessed as clean."
                ),
                agent_id=None,
                agent_name=_SYSTEM_RECORDER,
                source="runtime",
            )
            if outcome.get("success"):
                recorded.append(vuln_class)
            else:
                logger.warning(
                    "unexamined class %s was not recorded at finish: %s",
                    vuln_class,
                    outcome.get("error"),
                )
    except Exception:
        logger.exception("could not record unexamined classes at finish; finalizing anyway")
    return recorded


def _do_finish(  # noqa: PLR0911
    *,
    parent_id: str | None,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
    agent_graph: dict[str, Any],
    wind_down: str | None = None,
) -> dict[str, Any]:
    if parent_id is not None:
        return {
            "success": False,
            "error": (
                "This tool can only be used by the root/main agent. "
                "If you are a subagent, use agent_finish instead"
            ),
        }

    errors: list[str] = []
    if not executive_summary.strip():
        errors.append("Executive summary cannot be empty")
    if not methodology.strip():
        errors.append("Methodology cannot be empty")
    if not technical_analysis.strip():
        errors.append("Technical analysis cannot be empty")
    if not recommendations.strip():
        errors.append("Recommendations cannot be empty")
    if errors:
        return {"success": False, "error": "Validation failed", "errors": errors}

    # Closure gate: no lead may be left undisposed. A hypothesis is disposed by
    # reaching a terminal state in the model (confirmed, or refuted with its
    # grounds stated), by an inline disposition, or by an explicit deferral;
    # anything else blocks finishing. In a forced wind-down the leads the runtime
    # may record itself do not block — it publishes them as open further down,
    # because a rejected finish there can cost the scan its report.
    leads = _undisposed_leads_across_run()
    blocking_leads, runtime_leads = _split_for_wind_down(leads, wind_down)
    undisposed = _undisposed_hypotheses_across_run(blocking_leads)
    # Coverage gate, evaluated here — before anything is persisted or marked
    # complete — so a class nobody accounted for is still something the root agent
    # can act on, not a warning attached to a scan that has already ended. In a
    # forced wind-down it does not block: the runtime records the class itself
    # further down, because a rejected finish there can cost the scan its report.
    unrecorded = _unrecorded_classes(agent_graph)
    blocking: list[dict[str, Any]] = [] if wind_down else unrecorded
    if undisposed:
        logger.debug("finish_scan rejected — undisposed hypotheses: %s", undisposed)
        rejection = _closure_rejection(blocking_leads)
        # One rejection names both problems, so both are fixable in one turn.
        rejection.update(_coverage_rejection(blocking, error_key="coverage_error"))
        return rejection
    if blocking:
        logger.debug("finish_scan rejected — unrecorded hunt classes: %s", blocking)
        return {
            "success": False,
            "scan_completed": False,
            **_coverage_rejection(blocking, error_key="error"),
        }

    # Nothing blocks. Everything coverage-related is settled before the first
    # persistence side effect, and none of it can fail the finish.
    system_recorded = _record_unexamined(unrecorded, wind_down)
    system_undisposed = _record_undisposed_leads(runtime_leads, wind_down)
    coverage_summary = _advisory_coverage_summary(agent_graph, system_recorded, system_undisposed)

    try:
        from zen.report.state import get_global_report_state

        report_state = get_global_report_state()
        if report_state is None:
            logger.warning("No global report state; scan results not persisted")
            return {
                "success": True,
                "scan_completed": True,
                "message": "Scan completed (not persisted)",
                "warning": "Results could not be persisted - report state unavailable",
            }
        report_state.update_scan_final_fields(
            executive_summary=executive_summary.strip(),
            methodology=methodology.strip(),
            technical_analysis=technical_analysis.strip(),
            recommendations=recommendations.strip(),
        )
        vuln_count = len(report_state.vulnerability_reports)
    except (ImportError, AttributeError) as e:
        logger.exception("finish_scan persistence failed")
        return {"success": False, "error": f"Failed to complete scan: {e!s}"}
    else:
        logger.info(
            "finish_scan: completed scan with %d vulnerability report(s)",
            vuln_count,
        )
        result: dict[str, Any] = {
            "success": True,
            "scan_completed": True,
            "message": "Scan completed successfully",
            "vulnerabilities_found": vuln_count,
        }
        result.update(coverage_summary)
        return result


def _advisory_coverage_summary(
    agent_graph: dict[str, Any], system_recorded: list[str], system_undisposed: list[str]
) -> dict[str, Any]:
    """The advisory summary, computed before persistence and never fatal to it."""
    try:
        summary = _coverage_summary(agent_graph)
    except Exception:
        logger.exception("coverage summary failed; finishing without it")
        summary = {}
    if system_recorded:
        summary["system_recorded_unexamined"] = system_recorded
    if system_undisposed:
        summary["system_recorded_undisposed"] = system_undisposed
    return summary


def _coverage_summary(agent_graph: dict[str, Any]) -> dict[str, Any]:
    """Advisory coverage counts, unresolved surfaces, and gaps the runtime can see.

    The gap list here is derived from the skills agents carried, matched to
    ledger rows by wording. That reading is deliberately loose — a carried skill
    is not an assignment, and wording is not attribution — so it informs the
    response and the published record but never decides whether the scan may
    finish. The check that does is the coverage gate in :func:`_do_finish`,
    which reads only typed assignments and recorder identity.
    """
    from zen.report.coverage import agents_from_graph, skill_coverage_gaps
    from zen.tools.coverage.tools import get_coverage_entries, outcome_counts

    entries = get_coverage_entries()
    if not entries:
        return {
            "coverage_recorded": 0,
            "coverage_warning": (
                "No coverage was recorded for this scan. The report cannot show which "
                "surfaces were reviewed and cleared — only what was found. Use "
                "record_coverage during testing so future scans can report negative space."
            ),
        }

    counts = outcome_counts()
    summary: dict[str, Any] = {
        "coverage_recorded": len(entries),
        "coverage_outcomes": counts,
    }
    unresolved = [e for e in entries if e.get("outcome") == "needs_follow_up"]
    if unresolved:
        summary["coverage_warning"] = (
            f"{len(unresolved)} surface(s) closed as 'needs_follow_up' and remain "
            "unresolved. These should be represented in the report as areas requiring "
            "further review rather than omitted."
        )
        summary["unresolved_surfaces"] = [
            {"surface": e.get("surface", ""), "risk_area": e.get("risk_area", "")}
            for e in unresolved
        ]

    gaps = skill_coverage_gaps(entries, agents_from_graph(agent_graph))
    if gaps:
        summary["coverage_gaps"] = [gap["detail"] for gap in gaps]
        summary["coverage_gap_warning"] = (
            f"{len(gaps)} risk class(es) assigned to agents have no coverage entry and "
            "will be published as unexamined. Record them (or a needs_follow_up row) "
            "before the report goes out."
        )
    return summary


def _wind_down_reason(inner: dict[str, Any], coordinator: AgentCoordinator | None) -> str | None:
    """Why the runtime is forcing this scan to wrap up, or ``None`` when it is not.

    A forced wind-down is the runtime's own declaration, never the agent's: the
    scan budget or the sub-agent reserve was reached, or — in a run with no user
    attached to extend a limit — the final "finish immediately" warning stage is
    in force. In that state a rejected finish can cost the scan its report, so
    the coverage gate records what is unexamined itself instead of blocking.
    """
    from zen.core.hooks import FINAL_STAGE_KEY

    if coordinator is not None:
        if coordinator.budget_stopped:
            return "the scan budget was reached"
        if coordinator.reserve_stopped:
            return "the sub-agent budget reserve was reached"
    if not inner.get("interactive"):
        stage = inner.get(FINAL_STAGE_KEY)
        if isinstance(stage, str) and stage:
            return f"the {stage} was nearly exhausted"
    return None


@function_tool(timeout=60)
async def finish_scan(
    ctx: RunContextWrapper,
    executive_summary: str,
    methodology: str,
    technical_analysis: str,
    recommendations: str,
) -> str:
    """Finalize the scan — persist the customer-facing report.

    **Root-agent only.** Subagents must call ``agent_finish`` from the
    multi-agent graph tools instead. Calling this finalizes everything:

    1. Verifies you are the root agent.
    2. Writes the four narrative sections to the scan record.
    3. Marks the scan completed and stops execution.

    **This is a terminal action, not a status probe.** Whatever you pass
    is persisted VERBATIM as the final, customer-facing report and then
    execution stops. There is no draft mode and no second chance: never
    submit placeholder, provisional, or "checking if done" text in any
    field, and never call ``finish_scan`` to poll whether subagents are
    done (use ``view_agent_graph`` / ``wait_for_agents`` for that).
    Call it exactly ONCE, only when every field holds genuine, finished
    assessment prose.

    **Pre-flight checklist (mandatory — do not skip):**

    1. **Call ``view_agent_graph`` first.** Inspect every entry in the
       summary. If ANY agent is in ``running`` / ``waiting`` state,
       you MUST NOT call ``finish_scan`` yet —
       wrap them up first via ``send_message_to_agent`` (ask them to
       finish), ``wait_for_agents`` (block until their report
       arrives), or ``stop_agent`` (graceful cancel). Only ``completed``
       / ``crashed`` / ``stopped`` agents are safe to leave behind.
       Calling ``finish_scan`` while children are alive orphans their
       work and produces an incomplete report.
    2. It's a good idea to call ``list_reports`` before finishing to
       review every finding filed in this scan (use ``get_report`` for
       full detail on any of them) so your ``executive_summary`` /
       ``technical_analysis`` are grounded in what was actually reported
       — don't invent or omit findings. All vulnerabilities you found are
       filed via ``create_vulnerability_report`` — or, for known-CVE
       dependency findings, ``create_dependency_report`` (un-reported
       findings are not tracked and not credited). A dependency CVE
       already filed via ``create_dependency_report`` counts as reported;
       it does NOT need re-filing here and does NOT block finishing.
    3. Don't double-report — one report per distinct vulnerability.
    4. **Attack-chaining gate.** Do NOT finish until you have genuinely
       considered chaining the confirmed findings into higher-impact,
       end-to-end attack paths and tested every plausibly-related
       combination. You may rule out combinations you can confidently
       call unrelated — note why instead of padding chains. Any
       validated chain must already be filed via
       ``create_vulnerability_report`` — a demonstrated end-to-end chain
       is a PoC-backed vulnerability, so it uses that tool even when one
       link is a dependency CVE (the standalone CVE stays in its own
       ``create_dependency_report``) — and surfaced prominently in
       ``executive_summary`` / ``technical_analysis``. Finding no real
       chain after a serious attempt is acceptable; skipping the
       chaining reasoning, or ignoring a plausibly-related combination,
       is not.
    5. **Coverage reconciliation.** Call ``list_coverage`` and check
       what was actually assessed against the surfaces you enumerated
       during reconnaissance. Every surface you dispatched work on
       should have a coverage entry; anything still open should be a
       ``needs_follow_up`` row, not a silent omission. If a significant
       surface has no entry at all, dispatch an agent to cover it or
       record it as ``needs_follow_up`` before finishing. The response
       from this tool reports coverage counts and any unresolved rows.
    6. **Hypothesis disposition (closure gate).** Every threat-model
       hypothesis must be disposed of before finishing; ``finish_scan``
       refuses while any is undisposed — ``open``, ``blocked`` or
       ``testing`` with no recorded disposition, or ``refuted`` with no
       stated grounds — naming each and why. {closure_gate}
    7. **Coverage accounting (coverage gate).** {coverage_gate}

    **Calling this multiple times overwrites the previous report.**
    Make the single call comprehensive.

    **Report output rules** (this content may be rendered into generated
    reports):

    - Never mention internal infrastructure: no local/absolute paths
      (``/workspace/...``), no agent names, no sandbox/orchestrator/
      tooling references, no system prompts, no model-internal errors.
      Never leak internal identifiers (proxy request IDs, internal
      vulnerability report IDs, or any system-generated IDs) into any
      field.
    - Tone: formal, third-person, objective, concise. This is a
      consultant deliverable, not an engineering log.
    - Each section has a specific role:

        - ``executive_summary`` — for non-technical leadership. Risk
          posture, business impact (data exposure / compliance /
          reputation), notable criticals, overarching remediation
          theme.
        - ``methodology`` — frameworks followed (OWASP WSTG, PTES,
          OSSTMM, NIST), engagement type (black/gray/white box), scope
          and constraints, categories of testing performed. **No**
          internal execution detail.
        - ``technical_analysis`` — consolidated findings overview with
          severity model and systemic root causes. Reference individual
          vuln reports for repro steps; don't duplicate raw evidence.
        - ``recommendations`` — prioritized actions grouped by urgency
          (Immediate / Short-term / Medium-term), each with concrete
          remediation steps. End with retest/validation guidance.

    - **Formatting — use markdown in every field.** These fields may be
      rendered into generated reports, so structure them clearly: lead
      each section with a short ``# Heading``, use ``**bold**`` for labels/emphasis,
      ``inline code`` for identifiers/paths/parameters, bullet or
      numbered lists for enumerations, and fenced code blocks
      (```` ```language ````) for any code/payload excerpts. Never emit
      one flat wall of prose or leave code unformatted.
    - If **zero** vulnerabilities were found, say so plainly and
      characterize the posture positively; ``technical_analysis`` should
      summarize the areas tested and confirm no issues, and
      ``recommendations`` should focus on general hardening.

    Example (abbreviated — mirror this structure, not the wording)::

        executive_summary:
            # Executive Summary

            An external assessment of the **Acme Customer Portal**
            identified multiple weaknesses that could lead to
            unauthorized access to customer data.

            **Overall risk posture:** Elevated.

            **Key findings**
            - Confirmed SSRF in a URL-preview feature reaching internal
              network ranges.
            - Broken tenant isolation enabling cross-tenant data access.

            **Business impact**
            - Potential exposure of customer records across tenants.

        methodology:
            # Methodology

            Conducted per the **OWASP WSTG**.

            **Engagement type:** Gray-box external test.
            **Scope:** `https://app.acme.example`, `.../api/v1/`.

            **Activities:** recon, authn/session review, authorization
            and tenant-isolation testing, input/SSRF testing.

        technical_analysis:
            # Technical Analysis

            **Severity model** reflects exploitability x impact.

            1. **SSRF in URL preview** (Critical) — insufficient
               destination validation; reaches link-local addresses.
            2. **Broken tenant isolation** (High) — object identifiers
               accepted without ownership checks.

            **Systemic themes:** authorization enforced inconsistently;
            no deny-by-default egress policy.

        recommendations:
            # Recommendations

            **Immediate**
            1. Remediate SSRF: enforce a destination allowlist,
               deny-by-default, re-validate on every redirect hop.

            **Short-term**
            2. Centralize authorization with deny-by-default middleware.

            **Retest & validation:** re-test immediate items to confirm
            SSRF and tenant-isolation controls hold.

    Args:
        executive_summary: Business-level summary for leadership.
        methodology: Frameworks, scope, and approach.
        technical_analysis: Consolidated findings + systemic themes.
        recommendations: Prioritized, actionable remediation.
    """
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    coordinator = coordinator_from_context(inner)
    me = inner.get("agent_id")
    parent_id = inner.get("parent_id")
    if coordinator is not None and parent_id is None and me is not None:
        active_agents = await coordinator.active_agents_except(me)
        if active_agents and coordinator.reserve_stopped:
            active_agents = []
    else:
        active_agents = []

    if active_agents:
        return json.dumps(
            {
                "success": False,
                "scan_completed": False,
                "error": (
                    "Cannot finish scan while child agents are still active. "
                    "Wait for completion, send them finish instructions, or stop them first"
                ),
                "active_agents": active_agents,
            },
            ensure_ascii=False,
            default=str,
        )

    result = await asyncio.to_thread(
        _do_finish,
        parent_id=parent_id,
        executive_summary=executive_summary,
        methodology=methodology,
        technical_analysis=technical_analysis,
        recommendations=recommendations,
        agent_graph=await coordinator.snapshot() if coordinator is not None else {},
        wind_down=_wind_down_reason(inner, coordinator),
    )
    if (
        result.get("success")
        and result.get("scan_completed")
        and coordinator is not None
        and isinstance(me, str)
    ):
        await coordinator.set_status(me, "completed")
    return json.dumps(result, ensure_ascii=False, default=str)


# The coverage gate's teaching text is substituted from its single source, so the
# description the model reads cannot drift from the gate that enforces it.
finish_scan.description = finish_scan.description.replace(
    _COVERAGE_GATE_MARKER, _COVERAGE_GATE_TEACHING
)
finish_scan.description = finish_scan.description.replace(
    _CLOSURE_GATE_MARKER, _CLOSURE_GATE_TEACHING
)
