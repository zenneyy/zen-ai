"""The clean-context reviewer as a first-class role (Phase 2, item 2.2).

Item 2.2 reuses the Phase-1 role + generated-CONTRACT machinery to add the
reviewer: a persona whose METHOD is hand-written and whose CONTRACT is generated
from the live tool schemas and the verdict record. The deterministic validator
stays non-agent code, so ``validator`` keeps no persona and no CONTRACT.
"""

from __future__ import annotations

import pytest

from zen.agents.contract import (
    ROLE_TOOLS,
    UnknownRoleError,
    missing_requirements,
    registered_tool_names,
    render_contract,
    role_requirements,
)
from zen.agents.prompt import render_system_prompt
from zen.tools.agents_graph.tools import _REVIEWER_PERSONA, _role_persona_for
from zen.utils.resource_paths import get_zen_resource_path


def test_reviewer_contract_renders_and_surfaces_every_requirement() -> None:
    contract = render_contract("reviewer")
    assert "## CONTRACT (generated" in contract
    assert missing_requirements(contract, role_requirements("reviewer")) == []
    # The reviewer discipline is surfaced, class-agnostically.
    assert "clean context" in contract
    assert "reach_only" in contract
    assert "re-observe" in contract


def test_reviewer_owned_tools_are_all_real() -> None:
    assert set(ROLE_TOOLS["reviewer"]) <= registered_tool_names()
    for tool in ("get_threat_model", "record_coverage", "agent_finish"):
        assert tool in render_contract("reviewer")


def test_validator_role_has_no_generated_contract() -> None:
    """The deterministic validator is not an agent, so it has no CONTRACT — asking
    for one is surfaced loudly, not papered over with an empty contract."""
    with pytest.raises(UnknownRoleError):
        render_contract("validator")


def test_reviewer_persona_resolves_from_the_role() -> None:
    assert _role_persona_for("anything", [], role="reviewer") == (
        _REVIEWER_PERSONA,
        "role:reviewer",
    )


def test_reviewer_persona_file_is_method_only() -> None:
    body = (get_zen_resource_path("skills") / "coordination" / "reviewer_agent.md").read_text(
        encoding="utf-8"
    )
    assert "Reviewer Agent — Method" in body
    assert "## CONTRACT (generated" not in body
    assert render_contract("reviewer") not in body


def test_rendered_reviewer_prompt_is_method_plus_generated_contract() -> None:
    prompt = render_system_prompt(
        skills=["coordination/reviewer_agent"], is_root=False, scan_mode="deep"
    )
    assert "Reviewer Agent — Method" in prompt
    assert "## CONTRACT (generated" in prompt
