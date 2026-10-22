"""Structural auto-attach of a child's role persona when spawning via create_agent.

The prose rule in ``coordination/root_agent`` asks the caller to include a
spawned child's role persona in its skills list, but a ``create_agent`` call
that omits it still succeeds — the skip is silent, with no feedback loop. These
tests cover the backstop ``_maybe_attach_role_persona``: name- or skill-driven,
it attaches the matching persona before the child is built, after validation so
the structural skill never trips the user-skill checks, and without stacking a
duplicate when the caller already included it.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import pytest
from agents.tool_context import ToolContext

from zen.core.agents import AgentCoordinator
from zen.tools.agents_graph.tools import (
    _HUNTER_PERSONA,
    _RECON_PERSONA,
    _maybe_attach_role_persona,
    _role_persona_for,
    create_agent,
)


# --- trigger logic: _maybe_attach_role_persona / _role_persona_for ---------------


def test_recon_name_attaches_recon_persona() -> None:
    assert _maybe_attach_role_persona("Recon Agent", ["application_enumeration"]) == [
        _RECON_PERSONA,
        "application_enumeration",
    ]
    assert _role_persona_for("Recon Agent", ["application_enumeration"]) == (
        _RECON_PERSONA,
        "name_match",
    )


def test_hunter_name_attaches_hunter_persona() -> None:
    assert _maybe_attach_role_persona("Hunter", ["xss"]) == [_HUNTER_PERSONA, "xss"]
    assert _role_persona_for("Hunter", ["xss"]) == (_HUNTER_PERSONA, "name_match")


def test_name_match_is_case_insensitive() -> None:
    assert _maybe_attach_role_persona("DEEP RECON sweep", [])[0] == _RECON_PERSONA
    assert _maybe_attach_role_persona("xss HUNTER", [])[0] == _HUNTER_PERSONA


def test_persona_already_present_is_not_duplicated() -> None:
    skills = [_RECON_PERSONA, "application_enumeration"]
    result = _maybe_attach_role_persona("Recon Agent", skills)
    assert result == skills
    assert result.count(_RECON_PERSONA) == 1


def test_ambiguous_name_with_mixed_skills_gets_no_persona() -> None:
    skills = ["reconnaissance/asset_discovery", "xss"]
    assert _maybe_attach_role_persona("Scanner", skills) == skills
    assert _role_persona_for("Scanner", skills) == (None, None)


def test_non_role_name_with_bare_skills_gets_no_persona() -> None:
    # Bare vulnerability names carry no category prefix, so the skill fallback
    # cannot read a single category from them — it makes no guess.
    assert _maybe_attach_role_persona("SQLi Specialist", ["sql_injection"]) == ["sql_injection"]
    assert _role_persona_for("SQLi Specialist", ["sql_injection"]) == (None, None)


def test_uniform_recon_skills_trigger_fallback_persona() -> None:
    skills = ["reconnaissance/asset_discovery"]
    assert _maybe_attach_role_persona("Custom Agent", skills) == [_RECON_PERSONA, *skills]
    assert _role_persona_for("Custom Agent", skills) == (_RECON_PERSONA, "skill_fallback")


def test_uniform_vulnerability_skills_trigger_fallback_persona() -> None:
    skills = ["vulnerabilities/xss", "vulnerabilities/sql_injection"]
    assert _maybe_attach_role_persona("Custom Agent", skills) == [_HUNTER_PERSONA, *skills]
    assert _role_persona_for("Custom Agent", skills) == (_HUNTER_PERSONA, "skill_fallback")


def test_empty_skills_and_plain_name_get_no_persona() -> None:
    assert _maybe_attach_role_persona("Coordinator", []) == []
    assert _role_persona_for("Coordinator", []) == (None, None)


def test_input_list_is_not_mutated() -> None:
    skills = ["application_enumeration"]
    _maybe_attach_role_persona("Recon Agent", skills)
    assert skills == ["application_enumeration"]


# --- end-to-end through create_agent ---------------------------------------------


async def _spawn(name: str, skills: list[str], captured: dict[str, Any]) -> dict[str, Any]:
    """Invoke the create_agent tool with a stub spawner that records its kwargs."""
    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)

    async def _fake_spawner(**kwargs: Any) -> dict[str, Any]:
        captured.update(kwargs)
        return {
            "success": True,
            "agent_id": "child001",
            "name": kwargs["name"],
            "parent_id": "root",
        }

    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "root",
            "spawn_child_agent": _fake_spawner,
        },
        tool_name=create_agent.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await create_agent.on_invoke_tool(
        ctx, json.dumps({"name": name, "task": "probe the surface", "skills": skills})
    )
    return cast("dict[str, Any]", json.loads(raw))


@pytest.mark.asyncio
async def test_create_agent_delivers_persona_to_the_spawn_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    captured: dict[str, Any] = {}
    with caplog.at_level(logging.INFO, logger="zen.tools.agents_graph.tools"):
        result = await _spawn("Recon Agent", ["asset_discovery"], captured)

    assert result["success"] is True
    # The persona reached the spawner even though the caller never requested it,
    # and it was not rejected as an unknown skill (attach runs after validation).
    assert captured["skills"] == [_RECON_PERSONA, "asset_discovery"]
    assert "persona_autoattach" in caplog.text
    assert "trigger=name_match" in caplog.text
    assert "root_included=False" in caplog.text


@pytest.mark.asyncio
async def test_create_agent_leaves_a_non_role_child_untouched() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn("SQLi Specialist", ["sql_injection"], captured)

    assert result["success"] is True
    assert captured["skills"] == ["sql_injection"]
