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
from zen.tools.reporting.tool import create_vulnerability_report
from zen.tools.threat_model.schema import (
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
    ]


_ROLE_REQUIREMENTS = {
    "recon": _recon_requirements,
    "hunter": _hunter_requirements,
    "root": _root_requirements,
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
