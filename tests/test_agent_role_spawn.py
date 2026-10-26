"""Explicit-role spawn behavior for ``create_agent`` (item 1.1).

Role is now authoritative: ``create_agent(role="hunter", ...)`` attaches the
hunter persona regardless of the child's name or skills, the role→persona map is
the single source of truth, a persona-requiring role that resolves to no persona
fails the spawn loudly (on both the log and the returned error), and an
internal ``coordination/*`` slug passed in ``skills`` is refused with a specific,
actionable error distinct from the generic unknown-skill message.
"""

from __future__ import annotations

import json
import logging
from typing import Any, cast

import pytest
from agents.tool_context import ToolContext

from zen.core.agents import AgentCoordinator
from zen.tools.agents_graph import tools as agent_tools
from zen.tools.agents_graph.tools import (
    _HUNTER_PERSONA,
    _RECON_PERSONA,
    PersonaResolutionError,
    _resolve_effective_skills,
    _role_persona_for,
    create_agent,
)


async def _spawn(
    *, name: str, skills: list[str], role: str, captured: dict[str, Any], **args: Any
) -> dict[str, Any]:
    """Invoke create_agent with a stub spawner that records its kwargs."""
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
    payload = {"name": name, "task": "probe the surface", "skills": skills, "role": role, **args}
    raw: str = await create_agent.on_invoke_tool(ctx, json.dumps(payload))
    return cast("dict[str, Any]", json.loads(raw))


# --- role → persona map is authoritative -----------------------------------------


def test_role_map_resolves_directly_ignoring_name_and_skills() -> None:
    assert _role_persona_for("anything at all", [], role="hunter") == (
        _HUNTER_PERSONA,
        "role:hunter",
    )
    assert _role_persona_for("", ["xss"], role="recon") == (_RECON_PERSONA, "role:recon")


def test_roles_without_a_persona_yet_resolve_to_none() -> None:
    assert _role_persona_for("Scanner", ["xss"], role="validator") == (None, None)
    assert _role_persona_for("Scanner", ["xss"], role="reviewer") == (None, None)


@pytest.mark.asyncio
async def test_hunter_role_attaches_persona_with_a_neutral_name() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn(
        name="Surface Probe 7", skills=["sql_injection"], role="hunter", captured=captured
    )

    assert result["success"] is True
    assert captured["skills"] == [_HUNTER_PERSONA, "sql_injection"]
    assert captured["role"] == "hunter"


@pytest.mark.asyncio
async def test_hunter_role_attaches_persona_even_with_no_skills() -> None:
    # Name no longer matters: an empty skills list still gets the hunter persona.
    captured: dict[str, Any] = {}
    result = await _spawn(name="unlabelled", skills=[], role="hunter", captured=captured)

    assert result["success"] is True
    assert captured["skills"] == [_HUNTER_PERSONA]


@pytest.mark.asyncio
async def test_persona_attachment_logs_on_the_success_path(
    caplog: pytest.LogCaptureFixture,
) -> None:
    captured: dict[str, Any] = {}
    with caplog.at_level(logging.INFO, logger="zen.tools.agents_graph.tools"):
        await _spawn(
            name="Recon Sweep", skills=["asset_discovery"], role="recon", captured=captured
        )

    assert "persona_autoattach" in caplog.text
    assert "trigger=role:recon" in caplog.text


# --- persona-requiring role that cannot resolve a persona fails loudly ------------


def test_resolve_effective_skills_raises_when_required_persona_missing(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Drop the hunter entry from the role→persona map while leaving "hunter" in
    # the persona-required set: a required role now resolves to no persona.
    patched = dict(agent_tools._ROLE_PERSONA)
    patched.pop("hunter")
    monkeypatch.setattr(agent_tools, "_ROLE_PERSONA", patched)

    with (
        caplog.at_level(logging.ERROR, logger="zen.tools.agents_graph.tools"),
        pytest.raises(PersonaResolutionError),
    ):
        _resolve_effective_skills(role="hunter", name="any", skills=[])

    assert "persona_attach FAILED" in caplog.text
    assert "hunter" in caplog.text


@pytest.mark.asyncio
async def test_create_agent_fails_loudly_when_required_persona_missing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    patched = dict(agent_tools._ROLE_PERSONA)
    patched.pop("hunter")
    monkeypatch.setattr(agent_tools, "_ROLE_PERSONA", patched)

    captured: dict[str, Any] = {}
    result = await _spawn(name="any", skills=[], role="hunter", captured=captured)

    assert result["success"] is False
    assert "requires a role persona" in result["error"]
    # The spawn never reached the spawner.
    assert captured == {}


# --- internal coordination slug refused with a specific error ---------------------


@pytest.mark.asyncio
async def test_coordination_slug_in_skills_gets_the_specific_error() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn(
        name="Hunter", skills=["coordination/hunter_agent"], role="hunter", captured=captured
    )

    assert result["success"] is False
    # The specific coordination-slug error, NOT the generic unknown-skill one.
    assert "attached by role, not requested" in result["error"]
    assert "Invalid skill name" not in result["error"]
    assert captured == {}
