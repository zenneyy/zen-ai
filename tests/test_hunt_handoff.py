"""End-to-end typed hunt handoff through create_agent and agent_finish (item 1.2).

A hunter is spawned with a serialized ``hunt_task`` that is validated and rendered
into the child's first turn as a structured block; it must hand back a
``hunt_report`` at ``agent_finish``, whose digest (impact reached, variant leads)
is posted to the parent's inbox. Non-hunter roles keep the untyped free-text
path, so existing callers are unaffected.
"""

from __future__ import annotations

import json
from typing import Any, cast

import pytest
from agents.tool_context import ToolContext

from zen.core.agents import AgentCoordinator
from zen.report.state import set_global_report_state
from zen.tools.agents_graph.contracts import HuntReport, HuntScope, HuntTask
from zen.tools.agents_graph.tools import agent_finish, create_agent


def _hunt_task_json(**overrides: Any) -> str:
    task = HuntTask(
        objective="Prosecute the reflected search parameter.",
        vuln_class="xss",
        basis="observed",
        depth_tier="deep",
        impact_objective="primitive",
        scope=HuntScope(allow=["surface-1"]),
        rationale="Cheaper to prove directly than to route through the chain.",
    )
    data = task.model_dump(mode="json")
    data.update(overrides)
    return json.dumps(data)


async def _spawn(captured: dict[str, Any], **payload: Any) -> dict[str, Any]:
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
    base = {"name": "Probe", "task": "work the surface"}
    raw: str = await create_agent.on_invoke_tool(ctx, json.dumps({**base, **payload}))
    return cast("dict[str, Any]", json.loads(raw))


async def _finish_as_hunter(
    coordinator: AgentCoordinator, args: dict[str, Any]
) -> dict[str, Any]:
    ctx = ToolContext(
        context={
            "coordinator": coordinator,
            "agent_id": "child",
            "parent_id": "root",
            "role": "hunter",
        },
        tool_name=agent_finish.name,
        tool_call_id="call-1",
        tool_arguments="{}",
    )
    raw: str = await agent_finish.on_invoke_tool(ctx, json.dumps(args))
    return cast("dict[str, Any]", json.loads(raw))


# --- create_agent: hunt_task rendering -------------------------------------------


@pytest.mark.asyncio
async def test_hunter_hunt_task_is_rendered_into_the_child_first_turn() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn(captured, role="hunter", hunt_task=_hunt_task_json())

    assert result["success"] is True
    block = captured["hunt_task_block"]
    assert "== Hunt Task (structured delegation contract) ==" in block
    assert "Vulnerability class (exactly one): xss" in block
    assert captured["role"] == "hunter"


@pytest.mark.asyncio
async def test_hunt_task_for_a_non_hunter_role_is_rejected() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn(captured, role="recon", hunt_task=_hunt_task_json())

    assert result["success"] is False
    assert "only accepted for role='hunter'" in result["error"]
    assert captured == {}


@pytest.mark.asyncio
async def test_malformed_hunt_task_is_rejected() -> None:
    captured: dict[str, Any] = {}
    # Two vuln_class values — rejected at the schema level.
    result = await _spawn(
        captured, role="hunter", hunt_task=_hunt_task_json(vuln_class=["xss", "ssrf"])
    )

    assert result["success"] is False
    assert "invalid hunt_task" in result["error"]
    assert captured == {}


# --- backward compatibility: free-text path --------------------------------------


@pytest.mark.asyncio
async def test_non_hunter_spawn_uses_free_text_path() -> None:
    captured: dict[str, Any] = {}
    result = await _spawn(captured, role="generic", skills=["sql_injection"])

    assert result["success"] is True
    assert captured["hunt_task_block"] is None
    assert captured["skills"] == ["sql_injection"]


@pytest.mark.asyncio
async def test_hunter_without_hunt_task_still_spawns_free_text() -> None:
    # The typed path is additive — a hunter can still be delegated via free text.
    captured: dict[str, Any] = {}
    result = await _spawn(captured, role="hunter")

    assert result["success"] is True
    assert captured["hunt_task_block"] is None


# --- agent_finish: hunt_report required and digested -----------------------------


async def _hunter_graph() -> AgentCoordinator:
    set_global_report_state(None)
    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)
    await coordinator.register("child", "Hunter", parent_id="root", role="hunter")
    await coordinator.attach_runtime("root")
    await coordinator.attach_runtime("child")
    return coordinator


@pytest.mark.asyncio
async def test_hunter_finish_without_hunt_report_is_rejected() -> None:
    coordinator = await _hunter_graph()
    result = await _finish_as_hunter(coordinator, {"result_summary": "done"})

    assert result["success"] is False
    assert "must pass a hunt_report" in result["error"]
    # Still running — the finish did not take effect.
    assert coordinator.statuses["child"] == "running"


@pytest.mark.asyncio
async def test_hunter_finish_with_report_digests_to_parent_and_persists() -> None:
    coordinator = await _hunter_graph()
    report = HuntReport(
        impact_reached="weaponized",
        variant_leads=["second-order variant", "nested-context variant"],
        hypotheses_tested=["h1"],
    )

    result = await _finish_as_hunter(
        coordinator,
        {"result_summary": "confirmed and scoped", "hunt_report": report.model_dump_json()},
    )

    assert result["success"] is True
    assert result["hunt_report_recorded"] is True

    # The digest rode the completion report into the parent's inbox.
    body = coordinator.runtimes["root"].mailbox[0]["content"]
    assert "Hunt digest:" in body
    assert "impact_reached: weaponized" in body
    assert "second-order variant" in body

    # The full report was persisted to shared state.
    persisted = coordinator.metadata["child"]["hunt_report"]
    assert persisted["impact_reached"] == "weaponized"
    assert persisted["variant_leads"] == ["second-order variant", "nested-context variant"]


@pytest.mark.asyncio
async def test_hunter_finish_with_invalid_report_is_rejected() -> None:
    coordinator = await _hunter_graph()
    # filed_report_ids without a root_cause is an incomplete finding.
    bad = json.dumps({"filed_report_ids": ["vuln-1"], "impact_reached": "weaponized"})
    result = await _finish_as_hunter(
        coordinator, {"result_summary": "x", "hunt_report": bad}
    )

    assert result["success"] is False
    assert "invalid hunt_report" in result["error"]
    assert coordinator.statuses["child"] == "running"
