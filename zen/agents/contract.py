"""Generate each role's CONTRACT from the live schemas, validators, and gates.

A persona has two halves. METHOD is hand-written procedure and stopping
criteria (the ``coordination/*_agent.md`` files). CONTRACT is the obligations
half — the artifacts the role owns, the tools it must call and their required
fields, and the named gates its outputs must pass — and it is **never**
hand-written. This module is its single producer, rendering it at prompt-build
time from the same tool schemas and gate tables the role's outputs actually have
to satisfy. Because the gate that enforces and the text that teaches come from
one source, they cannot drift, and a validator requirement added anywhere
reaches every role's prompt the moment it exists. The prompt-contract alignment
test guards exactly that.

**Role → tools is not derivable from the agent factory.** Every role is granted
the same ``_BASE_TOOLS``; what differs is which tools a role *owns* — which gates
its outputs must pass. That ownership is a declared contract (:data:`ROLE_TOOLS`)
guarded by the alignment test, not a fact read out of the factory. An unknown
role raises rather than resolving to an empty, silently-wrong contract.

Nothing here caps the depth a researcher brings. The CONTRACT states *what a
sound output must carry* — evidence, a basis, a reproduction — at every level of
sophistication from a first-pass confirmation to original technique; it is the
floor every finding clears, not a ceiling on ambition.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, get_args

from zen.tools.agents_graph.contracts import HuntReport, HuntTask, ImpactRung
from zen.tools.agents_graph.tools import AgentRole, agent_finish, create_agent
from zen.tools.coverage.tools import list_coverage, record_coverage
from zen.tools.finish.tool import finish_scan
from zen.tools.hunt_topology.chains import (
    CONFIRMED_ADVANCEMENT_DESCRIPTION,
    DECOMPOSITION_GATE_DESCRIPTION,
    SINGLE_CONTEXT_DESCRIPTION,
)
from zen.tools.hunt_topology.discovery import (
    DISCOVERY_FANOUT_DESCRIPTION,
    EFFORT_SCALING_DESCRIPTION,
    UNSCOPED_EXPLORATION_DESCRIPTION,
)
from zen.tools.hunt_topology.tools import record_chain_plan
from zen.tools.ledger.objects import ValidatorVerdict
from zen.tools.reporting.tool import create_vulnerability_report
from zen.tools.threat_model.implied_classes import IMPLIED_CLASS_GATE_DESCRIPTION
from zen.tools.threat_model.schema import (
    DISMISSAL_LINE_EXAMPLE,
    DISPOSITION_CONVENTION,
    DISPOSITION_LINE_EXAMPLE,
    HYPOTHESIS_BASIS_VALUES,
    HYPOTHESIS_CONVENTION,
)
from zen.tools.threat_model.tools import (
    _REQUIRED_SECTIONS,
    amend_threat_model,
    get_threat_model,
    save_threat_model,
)


if TYPE_CHECKING:
    from agents.tool import FunctionTool

# The tools the CONTRACT can describe, resolved to their live objects from their
# source modules (not the factory — importing it here would cycle through
# zen.agents.prompt). Introspection reads these; nothing is granted per role by
# the factory, which gives every role the same set.
_ALL_TOOLS = (
    save_threat_model,
    amend_threat_model,
    get_threat_model,
    record_coverage,
    list_coverage,
    create_vulnerability_report,
    create_agent,
    agent_finish,
    finish_scan,
    record_chain_plan,
)
_TOOLS_BY_NAME = {tool.name: tool for tool in _ALL_TOOLS}


# ── role → owned tools (declared; see module docstring) ──────────────────────
#
# The tools whose gates each role's outputs must pass. Declared here because the
# factory grants every tool to every role, so this cannot be introspected from
# it. The alignment test asserts every name here is a real registered tool.

ROLE_TOOLS: dict[str, list[str]] = {
    "root": ["create_agent", "list_coverage", "finish_scan"],
    "recon": [
        "save_threat_model",
        "amend_threat_model",
        "get_threat_model",
        "record_coverage",
        "agent_finish",
    ],
    "hunter": [
        "create_vulnerability_report",
        "record_coverage",
        "amend_threat_model",
        "get_threat_model",
        "agent_finish",
    ],
    # The clean-context reviewer (2.2) owns the verdicts it authors: it reads the
    # shared model, records the coverage of what it re-observed, and hands back a
    # typed result. It does not file findings — it confirms or rejects them.
    "reviewer": [
        "get_threat_model",
        "record_coverage",
        "agent_finish",
    ],
    # The section-2.3 chaining composer owns the chain plan it records: it reads
    # the shared model, records the chain through the decomposition gate, covers
    # what it composed, and files the demonstrated end-to-end chain as a report.
    # It is a COMPOSER over single-class confirmed primitives, not a filer of
    # multi-class findings.
    "chaining": [
        "record_chain_plan",
        "get_threat_model",
        "record_coverage",
        "create_vulnerability_report",
        "agent_finish",
    ],
    # The section-2.3 bypassing composer owns the control characterization and the
    # defeat it records: it reads the shared model, amends it with the control it
    # characterized, covers the bypass attempt, and files the confirmed bypass.
    "bypassing": [
        "get_threat_model",
        "amend_threat_model",
        "record_coverage",
        "create_vulnerability_report",
        "agent_finish",
    ],
}

# A one-line statement of what each role's outputs are, rendered under "Artifacts
# you own". Role-descriptive, not tool-introspected — the role's reason to exist.
_ROLE_ARTIFACTS: dict[str, str] = {
    "root": (
        "the hunt plan and the reconciled final report; you own delegation and the "
        "coverage reconciliation, not hands-on testing."
    ),
    "recon": (
        "the shared threat model and the coverage ledger for the surfaces you map — the "
        "observed ground truth every other agent reasons over."
    ),
    "hunter": (
        "the vulnerability reports you file, the coverage entries for the approaches you "
        "try, and the typed hunt report you hand back."
    ),
    "reviewer": (
        "the verdicts you author — each confirming or rejecting a candidate finding on behavior "
        "you re-observed yourself, from a clean context, never on the hunter's narrative."
    ),
    "chaining": (
        "the chain compositions you record — each an ordered vector of distinct per-hop "
        "primitives toward an impact objective, advanced only on confirmed primitives — and the "
        "demonstrated end-to-end chain you file as a report. You compose; you do not hunt a class."
    ),
    "bypassing": (
        "the controls you characterize and the bypasses you confirm — each a control that blocked "
        "a primitive, defeated and validated so the blocked primitive advances toward "
        "confirmation. You defeat obstacles on a surface; you do not abandon it."
    ),
}


@dataclass(frozen=True)
class ContractRequirement:
    """One obligation the CONTRACT states. ``key`` must appear literally in the
    rendered text, so the alignment test can confirm it was surfaced."""

    key: str
    text: str
    group: str = "general"


class UnknownRoleError(ValueError):
    """A role with no declared owned-tool set — surfaced, never papered over."""


def registered_tool_names() -> set[str]:
    """Names of the real tool objects the CONTRACT resolves and describes."""
    return set(_TOOLS_BY_NAME)


def _tool(name: str) -> FunctionTool:
    """Resolve a tool name to its live object."""
    tool = _TOOLS_BY_NAME.get(name)
    if tool is None:
        msg = f"no registered tool named {name!r}"
        raise UnknownRoleError(msg)
    return tool


def tool_required_fields(name: str, *, declared: tuple[str, ...] | None = None) -> list[str]:
    """The contract-relevant required fields of a tool, from its live schema.

    Non-strict function tools expose a truthful ``required`` list, so it is used
    directly. Strict schemas mark *every* property required, so for those the
    caller passes the contract-relevant ``declared`` set and it is verified to
    exist among the tool's real properties (a renamed field breaks the test).
    """
    tool = _tool(name)
    schema = tool.params_json_schema
    required = [field for field in schema.get("required", []) if field != "ctx"]
    if not tool.strict_json_schema:
        return required
    if declared is None:
        return []
    properties = schema.get("properties", {})
    return [field for field in declared if field in properties]


def tool_properties(name: str) -> set[str]:
    """The property names a tool accepts (for verifying declared fields exist)."""
    return set(_tool(name).params_json_schema.get("properties", {}))


# Contract-relevant required fields for the strict tools whose schemas mark every
# property required. Verified against the live properties by the alignment test.
_RECORD_COVERAGE_FIELDS: tuple[str, ...] = (
    "surface",
    "risk_area",
    "outcome",
    "evidence",
    "approaches_tried",
)
_FINISH_SCAN_FIELDS: tuple[str, ...] = (
    "executive_summary",
    "methodology",
    "technical_analysis",
    "recommendations",
)
# Conditionally-required reporting evidence — enforced by create_vulnerability_report's
# own validators, not by its schema `required`, so surfaced explicitly.
_REPORT_EVIDENCE_FIELDS: tuple[str, ...] = ("http_exchange_ids", "code_locations", "fix_pr_body")


def _field_level_rule() -> ContractRequirement:
    return ContractRequirement(
        key="field-level error",
        group="rejection",
        text=(
            "Every gate below returns a field-level error naming the exact field to fix on "
            "rejection. Read the field it names and correct that — never loosen your output or "
            "route around the gate to make it pass."
        ),
    )


def _tool_requirement(name: str, *, declared: tuple[str, ...] | None = None) -> ContractRequirement:
    fields = tool_required_fields(name, declared=declared)
    required = ", ".join(fields) if fields else "(no required body fields)"
    return ContractRequirement(
        key=name,
        group="tools",
        text=f"`{name}` — required: {required}.",
    )


def _recon_requirements() -> list[ContractRequirement]:
    sections = " → ".join(_REQUIRED_SECTIONS)
    convention = " ".join(HYPOTHESIS_CONVENTION.describe())
    return [
        _tool_requirement("save_threat_model", declared=("target", "content")),
        _tool_requirement("amend_threat_model", declared=("target", "addendum")),
        _tool_requirement("get_threat_model", declared=("target",)),
        _tool_requirement("record_coverage", declared=_RECORD_COVERAGE_FIELDS),
        _tool_requirement("agent_finish", declared=("result_summary",)),
        ContractRequirement(
            key="required sections, in order",
            group="gates",
            text=(
                "`save_threat_model` replaces the whole document and gates it on these required "
                f"sections, in order: {sections}."
            ),
        ),
        ContractRequirement(
            key="basis of every hypothesis",
            group="gates",
            text=(
                "The basis of every hypothesis is one of "
                f"{', '.join(HYPOTHESIS_BASIS_VALUES)} — its evidentiary grounding, not a "
                "difficulty or depth rating."
            ),
        ),
        ContractRequirement(
            key=f"{HYPOTHESIS_CONVENTION.basis_marker}:",
            group="gates",
            text=f"Hypothesis convention — {convention}",
        ),
        ContractRequirement(
            key="discovery pass",
            group="gates",
            text=(
                "Every service reached indirectly (through a server-side request, an internal "
                "link, a redirect, or discovered credentials) must have a content/route "
                "discovery pass logged before the model is accepted; the save names any service "
                "that does not."
            ),
        ),
        ContractRequirement(
            key="architecture-implied class",
            group="gates",
            text=(
                f"{IMPLIED_CLASS_GATE_DESCRIPTION} Address every architecture-implied class "
                "before the model is accepted: name it in an `inferred_from_architecture` "
                "hypothesis (set its `vuln_class:` field), or record a reasoned dismissal under "
                f"a 'Dismissed Implied Classes' section (`{DISMISSAL_LINE_EXAMPLE}`). The save "
                "rejects, naming the class and the component or boundary that implied it, if any "
                "implied class is left neither hypothesized nor dismissed."
            ),
        ),
        ContractRequirement(
            key="disposition",
            group="gates",
            text=(
                f"{DISPOSITION_CONVENTION} A hypothesis left open or blocked with no disposition "
                f"blocks the scan from finishing and is named (`{DISPOSITION_LINE_EXAMPLE}`)."
            ),
        ),
    ]


def _hunter_requirements() -> list[ContractRequirement]:
    report_fields = ", ".join(HuntReport.model_fields)
    return [
        _tool_requirement("create_vulnerability_report"),
        _tool_requirement("record_coverage", declared=_RECORD_COVERAGE_FIELDS),
        _tool_requirement("amend_threat_model", declared=("target", "addendum")),
        _tool_requirement("get_threat_model", declared=("target",)),
        _tool_requirement("agent_finish", declared=("result_summary",)),
        ContractRequirement(
            key="http_exchange_ids",
            group="gates",
            text=(
                "A finding proven through the proxy is not fully filed until "
                "`http_exchange_ids` carries the request ids that prove it; a source finding "
                "carries its `code_locations` with the inline fix (`fix_pr_body`). These are "
                "enforced by the report's own validators."
            ),
        ),
        ContractRequirement(
            key="hunt_report",
            group="gates",
            text=(f"At `agent_finish` you owe a typed `hunt_report` carrying {report_fields}."),
        ),
        ContractRequirement(
            key="root_cause",
            group="gates",
            text=(
                "Any `filed_report_ids` in the `hunt_report` obliges a non-empty `root_cause` — "
                "a filed finding without a stated root cause is incomplete."
            ),
        ),
    ]


def _root_requirements() -> list[ContractRequirement]:
    hunt_fields = ", ".join(name for name, f in HuntTask.model_fields.items() if f.is_required())
    roles = ", ".join(get_args(AgentRole))
    impact_ladder = " → ".join(get_args(ImpactRung))
    return [
        _tool_requirement("create_agent", declared=("name", "task", "role")),
        _tool_requirement("list_coverage"),
        _tool_requirement("finish_scan", declared=_FINISH_SCAN_FIELDS),
        ContractRequirement(
            key="hunt_task",
            group="gates",
            text=(
                "Delegate a hunter with a typed `hunt_task`; its required fields are "
                f"{hunt_fields}. Exactly one `vuln_class` is enforced structurally."
            ),
        ),
        ContractRequirement(
            key="role=",
            group="gates",
            text=(
                f"Set `role=` on every `create_agent` (one of {roles}); the role attaches the "
                "persona and makes the handoff typed. Do not pass `coordination/*` in `skills`."
            ),
        ),
        ContractRequirement(
            key="impact ladder",
            group="gates",
            text=(
                "A hunt's `impact_objective` names a rung on the impact ladder "
                f"({impact_ladder}) — consequence, not difficulty."
            ),
        ),
        ContractRequirement(
            key="closure gate",
            group="gates",
            text=(
                "The closure gate on `finish_scan` refuses while any threat-model hypothesis is "
                f"left open or blocked with no recorded disposition. {DISPOSITION_CONVENTION} "
                "Resolve each open/blocked lead to a terminal state, give it an inline disposition "
                f"(`{DISPOSITION_LINE_EXAMPLE}`), or defer it, before you finish."
            ),
        ),
        ContractRequirement(
            key="Parallel discovery fan-out",
            group="gates",
            text=f"Parallel discovery fan-out — {DISCOVERY_FANOUT_DESCRIPTION}",
        ),
        ContractRequirement(
            key="Effort-scaling",
            group="gates",
            text=f"Effort-scaling — {EFFORT_SCALING_DESCRIPTION}",
        ),
        ContractRequirement(
            key="Unscoped exploration",
            group="gates",
            text=f"Unscoped exploration — {UNSCOPED_EXPLORATION_DESCRIPTION}",
        ),
    ]


_REVIEWER_VERDICT_FIELDS: tuple[str, ...] = (
    "passed",
    "reach_only",
    "author",
    "oracle_signal",
    "replayed_evidence_ids",
)


def _reviewer_requirements() -> list[ContractRequirement]:
    verdict_fields = ", ".join(
        name for name in ValidatorVerdict.model_fields if name in _REVIEWER_VERDICT_FIELDS
    )
    return [
        _tool_requirement("get_threat_model", declared=("target",)),
        _tool_requirement("record_coverage", declared=_RECORD_COVERAGE_FIELDS),
        _tool_requirement("agent_finish", declared=("result_summary",)),
        ContractRequirement(
            key="clean context",
            group="gates",
            text=(
                "You review from a clean context: you are handed the re-executable evidence and "
                "the target, never the hunter's narrative, hypothesis, or reasoning. Ground every "
                "verdict in behavior you re-observe yourself, so it cannot rest on the story you "
                "were told."
            ),
        ),
        ContractRequirement(
            key="reach_only",
            group="gates",
            text=(
                "Confirmation is re-observation, not belief: a candidate is confirmed only when "
                "you re-execute its evidence and observe the role-/tenant-/state-differential "
                "effect first-hand. Reaching the surface again is not enough — a re-reach with no "
                "re-observed effect is `reach_only`, which does not confirm."
            ),
        ),
        ContractRequirement(
            key="verdict is attributable",
            group="gates",
            text=(
                "Your verdict is attributable and explicit: it records "
                f"{verdict_fields} — who authored it, whether it only reached the surface, and the "
                "re-observed signal that grounds a confirmation. A confirmation carries that "
                "signal; a rejection says what it re-observed instead."
            ),
        ),
    ]


def _chaining_requirements() -> list[ContractRequirement]:
    impact_ladder = " → ".join(get_args(ImpactRung))
    return [
        _tool_requirement("record_chain_plan", declared=("chain_plan",)),
        _tool_requirement("get_threat_model", declared=("target",)),
        _tool_requirement("record_coverage", declared=_RECORD_COVERAGE_FIELDS),
        _tool_requirement("create_vulnerability_report"),
        _tool_requirement("agent_finish", declared=("result_summary",)),
        ContractRequirement(
            key="Per-hop distinct-class decomposition",
            group="gates",
            text=f"Per-hop distinct-class decomposition — {DECOMPOSITION_GATE_DESCRIPTION}",
        ),
        ContractRequirement(
            key="Confirmed-primitive advancement",
            group="gates",
            text=f"Confirmed-primitive advancement — {CONFIRMED_ADVANCEMENT_DESCRIPTION}",
        ),
        ContractRequirement(
            key="Single long-lived context",
            group="gates",
            text=f"Single long-lived context — {SINGLE_CONTEXT_DESCRIPTION}",
        ),
        ContractRequirement(
            key="impact ladder",
            group="gates",
            text=(
                f"Compose along the impact ladder ({impact_ladder}) — consequence, not "
                "difficulty. The chain is claimed to a rung only when every hop up to and "
                "including the terminal hop is confirmed."
            ),
        ),
        ContractRequirement(
            key="single-class composition",
            group="gates",
            text=(
                "You are a single-class composition role: each hop's primitive stays a "
                "single-class finding confirmed via the validator path, and you do not file "
                "multi-class findings. The demonstrated end-to-end chain itself is filed with "
                "`create_vulnerability_report`."
            ),
        ),
    ]


def _bypassing_requirements() -> list[ContractRequirement]:
    return [
        _tool_requirement("get_threat_model", declared=("target",)),
        _tool_requirement("amend_threat_model", declared=("target", "addendum")),
        _tool_requirement("record_coverage", declared=_RECORD_COVERAGE_FIELDS),
        _tool_requirement("create_vulnerability_report"),
        _tool_requirement("agent_finish", declared=("result_summary",)),
        ContractRequirement(
            key="Characterize-then-defeat",
            group="gates",
            text=(
                "Characterize-then-defeat — treat every control that blocks the current primitive "
                "as an obstacle to characterize then defeat, never a reason to abandon the "
                "surface: identify the control, model why it blocks the primitive, attempt to "
                "defeat or route through it, and empirically validate the bypass. The procedure "
                "is generic — it names no specific control or technique."
            ),
        ),
        ContractRequirement(
            key="Confirm the bypass via the validator path",
            group="gates",
            text=(
                "Confirm the bypass via the validator path — a defeated control is evidence that "
                "advances the blocked primitive toward confirmation; the primitive reaches "
                "'confirmed' only through a passing validator verdict (the same confirmed notion "
                "the validator socket enforces), never because the surface was reached again."
            ),
        ),
        ContractRequirement(
            key="The surface is not abandoned",
            group="gates",
            text=(
                "The surface is not abandoned — the characterized control and the defeat attempt "
                "are recorded: a surface under a control is covered with the bypass attempt and "
                "its outcome, not silently abandoned. A control you cannot defeat this engagement "
                "is recorded as such — with the gap — as a disposition, never dropped."
            ),
        ),
        ContractRequirement(
            key="one long-lived context",
            group="gates",
            text=(
                "You run in one long-lived context — bypassing is dependency-heavy, not "
                "breadth-parallel, so you hold the whole characterize→defeat→validate loop in one "
                "context rather than fragmenting it across short-lived agents."
            ),
        ),
    ]


_ROLE_REQUIREMENTS = {
    "recon": _recon_requirements,
    "hunter": _hunter_requirements,
    "root": _root_requirements,
    "reviewer": _reviewer_requirements,
    "chaining": _chaining_requirements,
    "bypassing": _bypassing_requirements,
}


def role_requirements(role: str) -> list[ContractRequirement]:
    """The obligations a role's CONTRACT states, derived from live sources.

    Raises :class:`UnknownRoleError` for a role with no declared contract — the
    missing mapping is surfaced, not silently rendered as an empty contract.
    """
    builder = _ROLE_REQUIREMENTS.get(role)
    if builder is None:
        msg = f"no CONTRACT is defined for role {role!r}"
        raise UnknownRoleError(msg)
    return [_field_level_rule(), *builder()]


_GROUP_HEADINGS = {
    "rejection": "On rejection",
    "tools": "Tools you must call, and what each requires",
    "gates": "Gates your outputs must pass",
    "general": "",
}


def render_contract(role: str) -> str:
    """Render ``role``'s CONTRACT section (METHOD + this is the full persona)."""
    if role not in ROLE_TOOLS:
        msg = f"no owned-tool set is declared for role {role!r}"
        raise UnknownRoleError(msg)
    requirements = role_requirements(role)

    lines: list[str] = [
        "## CONTRACT (generated — do not hand-edit)",
        "",
        "This section is generated from the live tool schemas and the gates your outputs "
        "must pass (see `zen/agents/contract.py`); it is the floor every output clears, at "
        "every level of sophistication, not a ceiling on what you may attempt.",
        "",
        "### Artifacts you own",
        f"- {_ROLE_ARTIFACTS[role]}",
        "",
    ]
    for group in ("rejection", "tools", "gates"):
        group_reqs = [req for req in requirements if req.group == group]
        if not group_reqs:
            continue
        heading = _GROUP_HEADINGS[group]
        if heading:
            lines.append(f"### {heading}")
        lines.extend(f"- {req.text}" for req in group_reqs)
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def missing_requirements(rendered: str, requirements: list[ContractRequirement]) -> list[str]:
    """Keys of requirements whose marker is absent from ``rendered`` (test helper)."""
    return [req.key for req in requirements if req.key not in rendered]


__all__ = [
    "ROLE_TOOLS",
    "ContractRequirement",
    "UnknownRoleError",
    "missing_requirements",
    "registered_tool_names",
    "render_contract",
    "role_requirements",
    "tool_properties",
    "tool_required_fields",
]
