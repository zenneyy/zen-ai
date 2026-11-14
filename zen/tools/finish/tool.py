"""``finish_scan`` — root-agent termination + executive report persistence."""

from __future__ import annotations

import asyncio
import json
import logging
from typing import TYPE_CHECKING, Any

from agents import RunContextWrapper, function_tool

from zen.core.agents import coordinator_from_context


if TYPE_CHECKING:
    from zen.core.agents import AgentCoordinator


logger = logging.getLogger(__name__)


# Hypothesis states that leave a lead unresolved. A hypothesis in one of these
# must carry a recorded disposition before the scan can finish; ``testing`` is in
# progress (being handled), and ``confirmed``/``refuted`` are already terminal.
_OPEN_HYPOTHESIS_STATES = frozenset({"open", "blocked"})


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


def _undisposed_open_hypotheses(content: str) -> list[str]:
    """Ids of open/blocked hypotheses in one model with no recorded disposition.

    A hypothesis counts as disposed when any one of these holds:

    * it is in a terminal state (``confirmed``/``refuted``) — then it is not
      open/blocked in the first place;
    * it carries an inline ``disposition`` on its own hypothesis line — the
      low-friction channel (``deferred`` / ``accepted_risk`` / ``out_of_scope`` /
      ``resolved_elsewhere``, validated by :class:`~zen.tools.threat_model.schema.Hypothesis`); or
    * a ``## Deferred Hypotheses`` record names its id — the dedicated channel.

    Anything left open or blocked with none of these is an undisposed lead and is
    returned by id. Both disposition channels are read from the same schema
    definitions the save validates against, so the gate accepts exactly what the
    schema lets a hypothesis express — the fix for the save/finish deadlock where
    the gate demanded a disposition the schema forbade recording.
    """
    from zen.tools.threat_model.schema import parse_deferrals, parse_hypotheses

    hypotheses, _ = parse_hypotheses(content)
    deferrals, _ = parse_deferrals(content)
    deferred = {deferral.hypothesis_id for deferral in deferrals}
    return [
        h.id
        for h in hypotheses
        if h.state in _OPEN_HYPOTHESIS_STATES and h.disposition is None and h.id not in deferred
    ]


def _undisposed_from_ledger(ledger: object) -> list[str]:
    """The closure gate as a query over the ledger's typed hypotheses.

    For each saved document, the open/blocked hypotheses are read as typed
    :class:`~zen.tools.threat_model.schema.Hypothesis` rows (their ``state`` and
    inline ``disposition`` are object fields, not re-parsed prose); the dedicated
    ``## Deferred Hypotheses`` dispositions — the other disposition channel — are
    read from the document view the ledger projects. Behavior-equivalent to the
    prose path: the typed rows were parsed from the same body, and the deferral
    grammar is the same.
    """
    from zen.tools.threat_model.schema import parse_deferrals

    seen: set[str] = set()
    ordered: list[str] = []
    for identity in ledger.model_identities():  # type: ignore[attr-defined]
        hypotheses = ledger.get_hypotheses(identity)  # type: ignore[attr-defined]
        view = ledger.get_model_view(identity)  # type: ignore[attr-defined]
        deferrals, _ = parse_deferrals(str(view.get("content", "")) if view else "")
        deferred = {d.hypothesis_id for d in deferrals}
        for hypothesis in hypotheses:
            if (
                hypothesis.state in _OPEN_HYPOTHESIS_STATES
                and hypothesis.disposition is None
                and hypothesis.id not in deferred
                and hypothesis.id not in seen
            ):
                seen.add(hypothesis.id)
                ordered.append(hypothesis.id)
    return ordered


def _undisposed_hypotheses_across_run() -> list[str]:
    """Undisposed open/blocked hypothesis ids across every threat model this run holds.

    Queries the run-scoped research ledger's typed hypotheses when one is
    installed, and falls back to parsing the threat-model dict store otherwise.
    With no model saved — the common case — there are no hypotheses and the
    closure gate is a no-op pass.
    """
    from zen.tools.ledger.runtime import get_ledger

    ledger = get_ledger()
    if ledger is not None and ledger.has_models():
        return _undisposed_from_ledger(ledger)

    from zen.tools.threat_model.tools import _MODELS, _store_lock

    with _store_lock:
        contents = [
            str(model.get("content", ""))
            for model in _MODELS.values()
            if isinstance(model, dict)
        ]
    seen: set[str] = set()
    ordered: list[str] = []
    for content in contents:
        for hypothesis_id in _undisposed_open_hypotheses(content):
            if hypothesis_id not in seen:
                seen.add(hypothesis_id)
                ordered.append(hypothesis_id)
    return ordered


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

    # Closure gate: no lead may be left open or blocked without a recorded
    # disposition. A hypothesis is disposed by reaching a terminal state in the
    # model (confirmed/refuted) or by an explicit deferral carrying it forward;
    # anything else blocks finishing, so a dropped lead is structurally impossible
    # to leave unrecorded.
    undisposed = _undisposed_hypotheses_across_run()
    # Coverage gate, evaluated here — before anything is persisted or marked
    # complete — so a class nobody accounted for is still something the root agent
    # can act on, not a warning attached to a scan that has already ended. In a
    # forced wind-down it does not block: the runtime records the class itself
    # further down, because a rejected finish there can cost the scan its report.
    unrecorded = _unrecorded_classes(agent_graph)
    blocking: list[dict[str, Any]] = [] if wind_down else unrecorded
    if undisposed:
        from zen.tools.threat_model.schema import (
            DEFERRAL_LINE_EXAMPLE,
            DISPOSITION_LINE_EXAMPLE,
        )

        logger.debug("finish_scan rejected — undisposed open/blocked hypotheses: %s", undisposed)
        rejection: dict[str, Any] = {
            "success": False,
            "scan_completed": False,
            "error": (
                "Closure gate: the scan cannot finish while these threat-model hypotheses are "
                f"still open or blocked with no recorded disposition: {', '.join(undisposed)}. "
                "Dispose of each — resolve it to a terminal state (confirmed or refuted) in the "
                "model, record an inline disposition on its hypothesis line "
                f"(`{DISPOSITION_LINE_EXAMPLE}`), or carry it forward under a 'Deferred "
                f"Hypotheses' section (`{DEFERRAL_LINE_EXAMPLE}`). A lead is disposed of, never "
                "dropped silently."
            ),
            "undisposed_hypotheses": undisposed,
        }
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
    coverage_summary = _advisory_coverage_summary(agent_graph, system_recorded)

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
    agent_graph: dict[str, Any], system_recorded: list[str]
) -> dict[str, Any]:
    """The advisory summary, computed before persistence and never fatal to it."""
    try:
        summary = _coverage_summary(agent_graph)
    except Exception:
        logger.exception("coverage summary failed; finishing without it")
        summary = {}
    if system_recorded:
        summary["system_recorded_unexamined"] = system_recorded
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
       hypothesis still ``open`` or ``blocked`` must be disposed of
       before finishing, in any one of three ways: resolved to a
       terminal state (``confirmed`` / ``refuted``) in the model; marked
       with an inline ``disposition:`` field on its own hypothesis line
       (one of ``deferred`` / ``accepted_risk`` / ``out_of_scope`` /
       ``resolved_elsewhere``, optionally a ``disposition_reason:``); or
       carried forward under a ``## Deferred Hypotheses`` section
       (``- hypothesis_id: <id> | reason: <why it is carried forward>``).
       A lead you could neither confirm nor rule out is disposed of, not
       dropped — ``finish_scan`` refuses while any undisposed open or
       blocked hypothesis remains, naming it.
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
