"""Prompt-contract alignment (item 1.4).

The CONTRACT half of each persona is generated from the live tool schemas and
gates (:mod:`zen.agents.contract`); the persona ``.md`` files carry METHOD only.
These tests pin that the two never drift:

* every validator-enforced requirement a role's tools impose is surfaced in that
  role's rendered CONTRACT — and the check has teeth (a requirement with no
  CONTRACT mention is reported missing);
* the requirements are anchored to the *live* sources (the required-section
  table, the basis enum, the report's required fields, the hunt-task schema),
  not to a parallel hand-list;
* every ``category/name`` slug in each persona's METHOD validates or names a
  framework-injected module;
* the CONTRACT is generated, never hand-written into the persona files.

Everything here is class-agnostic.
"""

from __future__ import annotations

import re
from typing import get_args

import pytest

from zen.agents.contract import (
    _FINISH_SCAN_FIELDS,
    _RECORD_COVERAGE_FIELDS,
    _REPORT_EVIDENCE_FIELDS,
    ROLE_TOOLS,
    ContractRequirement,
    UnknownRoleError,
    missing_requirements,
    registered_tool_names,
    render_contract,
    role_requirements,
    tool_properties,
    tool_required_fields,
)
from zen.agents.prompt import render_system_prompt
from zen.skills import _INTERNAL_SKILL_CATEGORIES, validate_requested_skills
from zen.tools.agents_graph.contracts import HuntBasis, HuntTask
from zen.tools.coverage.tools import record_coverage
from zen.tools.finish.tool import finish_scan
from zen.tools.threat_model.implied_classes import IMPLIED_CLASS_GATE_DESCRIPTION
from zen.tools.threat_model.schema import (
    DISMISSAL_LINE_EXAMPLE,
    DISPOSITION_CONVENTION,
    DISPOSITION_LINE_EXAMPLE,
    HYPOTHESIS_DISPOSITION_VALUES,
)
from zen.tools.threat_model.tools import _REQUIRED_SECTIONS
from zen.utils.resource_paths import get_zen_resource_path


ROLES = ("root", "recon", "hunter")
_PERSONA_VAR = {"root": "root_agent", "recon": "recon_agent", "hunter": "hunter_agent"}
_METHOD_MARKER = {
    "root": "Root Agent — Method",
    "recon": "Recon Agent — Method",
    "hunter": "Hunter Agent — Method",
}

_SLUG_RE = re.compile(r"`([a-z_]+)/([a-z0-9_]+)`")


# --- completeness + teeth --------------------------------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_every_derived_requirement_is_surfaced(role: str) -> None:
    contract = render_contract(role)
    requirements = role_requirements(role)
    assert requirements, "a role with no requirements would make this vacuous"
    assert missing_requirements(contract, requirements) == []


@pytest.mark.parametrize("role", ROLES)
def test_alignment_check_fails_on_an_unmentioned_requirement(role: str) -> None:
    """A validator requirement with no CONTRACT mention is reported missing.

    This is the drift guard: a deliberately-added requirement the renderer does
    not surface must be flagged, so a real new validator requirement cannot slip
    past unmentioned.
    """
    contract = render_contract(role)
    fake = ContractRequirement(key="__requirement_the_contract_never_mentions__", text="x")
    assert missing_requirements(contract, [*role_requirements(role), fake]) == [
        "__requirement_the_contract_never_mentions__"
    ]


# --- anchored to the live validator sources --------------------------------------


def test_recon_contract_names_save_threat_model_and_the_six_sections_in_order() -> None:
    contract = render_contract("recon")
    assert "save_threat_model" in contract
    lowered = contract.lower()
    indices = [lowered.find(section) for section in _REQUIRED_SECTIONS]
    assert all(index >= 0 for index in indices), list(zip(_REQUIRED_SECTIONS, indices, strict=True))
    assert indices == sorted(indices)
    assert len(set(indices)) == len(indices)


def test_recon_contract_names_the_basis_enum_and_the_hypothesis_convention() -> None:
    contract = render_contract("recon")
    for basis in get_args(HuntBasis):
        assert basis in contract
    # The greppable convention markers the save gate parses.
    assert "basis:" in contract
    assert " | " in contract


def test_recon_contract_names_the_discovery_pass_gate() -> None:
    assert "discovery pass" in render_contract("recon")


def test_recon_contract_names_the_architecture_implied_completeness_gate() -> None:
    """The item-1.5 completeness gate is surfaced in recon's CONTRACT, sourced
    from the same description and dismissal grammar the save gate enforces."""
    contract = render_contract("recon")
    assert "architecture-implied class" in contract
    # Both ways to address an implied class are taught, from the live sources.
    assert "inferred_from_architecture" in contract
    assert "vuln_class:" in contract
    assert DISMISSAL_LINE_EXAMPLE in contract
    # The teaching text is the gate's own description (single source, no drift).
    assert IMPLIED_CLASS_GATE_DESCRIPTION in contract


def test_recon_contract_names_the_hypothesis_disposition_convention() -> None:
    """Recon owns the threat model, so its CONTRACT teaches how an open/blocked
    hypothesis is disposed — sourced from the same schema constants the closure
    gate reads, so the text that teaches and the gate that enforces cannot drift."""
    contract = render_contract("recon")
    assert DISPOSITION_CONVENTION in contract
    assert DISPOSITION_LINE_EXAMPLE in contract
    for value in HYPOTHESIS_DISPOSITION_VALUES:
        assert value in contract, value


def test_root_contract_names_the_closure_gate_disposition() -> None:
    """Root owns ``finish_scan``, so its CONTRACT surfaces the closure gate: finish
    is blocked until every open/blocked hypothesis is disposed, by the exact inline
    format the gate accepts."""
    contract = render_contract("root")
    assert "closure gate" in contract.lower()
    assert DISPOSITION_CONVENTION in contract
    assert DISPOSITION_LINE_EXAMPLE in contract


def test_hunter_contract_surfaces_the_reports_required_fields() -> None:
    contract = render_contract("hunter")
    for field in tool_required_fields("create_vulnerability_report"):
        assert field in contract, field
    assert "hunt_report" in contract
    assert "root_cause" in contract


def test_root_contract_surfaces_the_hunt_task_required_fields() -> None:
    contract = render_contract("root")
    for name, field in HuntTask.model_fields.items():
        if field.is_required():
            assert name in contract, name


# --- role → owned tools are real; declared strict fields match the schema --------


@pytest.mark.parametrize("role", ROLES)
def test_owned_tools_are_all_real(role: str) -> None:
    assert set(ROLE_TOOLS[role]) <= registered_tool_names()


def test_strict_tool_declared_fields_match_their_live_schema() -> None:
    def required(tool: object) -> set[str]:
        schema = tool.params_json_schema  # type: ignore[attr-defined]
        return {field for field in schema.get("required", []) if field != "ctx"}

    # record_coverage and finish_scan have no optional params, so the declared
    # contract fields must equal their real schema-required set.
    assert set(_RECORD_COVERAGE_FIELDS) == required(record_coverage)
    assert set(_FINISH_SCAN_FIELDS) == required(finish_scan)
    # The conditionally-required reporting evidence fields really exist on the tool.
    assert set(_REPORT_EVIDENCE_FIELDS) <= tool_properties("create_vulnerability_report")


# --- METHOD-only personas; CONTRACT is generated ---------------------------------


@pytest.mark.parametrize("role", ROLES)
def test_persona_file_is_method_only(role: str) -> None:
    coordination = get_zen_resource_path("skills") / "coordination"
    body = (coordination / f"{_PERSONA_VAR[role]}.md").read_text(encoding="utf-8")
    assert _METHOD_MARKER[role] in body
    # The generated CONTRACT is never hand-written into the persona file.
    assert "## CONTRACT (generated" not in body
    assert render_contract(role) not in body


@pytest.mark.parametrize("role", ROLES)
def test_rendered_prompt_carries_method_plus_generated_contract(role: str) -> None:
    skills = [] if role == "root" else [f"coordination/{_PERSONA_VAR[role]}"]
    prompt = render_system_prompt(skills=skills, is_root=(role == "root"), scan_mode="deep")
    assert _METHOD_MARKER[role] in prompt
    assert "## CONTRACT (generated" in prompt


# --- slug hygiene in METHOD ------------------------------------------------------


@pytest.mark.parametrize("var", list(_PERSONA_VAR.values()))
def test_method_slugs_validate_or_are_framework_injected(var: str) -> None:
    skills_dir = get_zen_resource_path("skills")
    body = (skills_dir / "coordination" / f"{var}.md").read_text(encoding="utf-8")
    offenders: list[str] = []
    for category, name in _SLUG_RE.findall(body):
        slug = f"{category}/{name}"
        passable = validate_requested_skills([slug]) is None
        framework = category in _INTERNAL_SKILL_CATEGORIES and (skills_dir / f"{slug}.md").is_file()
        if not (passable or framework):
            offenders.append(slug)
    assert offenders == []


def test_unknown_role_is_surfaced_not_silently_empty() -> None:
    with pytest.raises(UnknownRoleError):
        render_contract("validator")
