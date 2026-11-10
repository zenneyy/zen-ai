"""The bypassing agent as a first-class role (Phase 2, item 2.3).

The bypassing agent reuses the Phase-1 role + generated-CONTRACT machinery and
runs in one long-lived context. Its discipline is to treat a control that blocks
a primitive as an obstacle to *characterize then defeat*, never a reason to
abandon the surface: characterize the control, record the defeat attempt, and
confirm the bypass through the **same validator socket** every other confirmation
uses — so a defeated control advances the blocked primitive to ``confirmed``,
while a bypass that only reached the surface again does not.

Everything here is class-agnostic: the control is a generic, unnamed mechanism,
the defeat a generic replay; no specific control or technique is named.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zen.agents.contract import (
    ROLE_TOOLS,
    missing_requirements,
    registered_tool_names,
    render_contract,
    role_requirements,
)
from zen.agents.prompt import render_system_prompt
from zen.tools.agents_graph.tools import (
    _BYPASSING_PERSONA,
    _PERSONA_REQUIRED_ROLES,
    _role_persona_for,
)
from zen.tools.ledger.objects import (
    CoverageCell,
    Evidence,
    EvidenceReplay,
    Finding,
    ValidatorVerdict,
)
from zen.tools.ledger.store import ResearchLedger, VerdictError
from zen.utils.resource_paths import get_zen_resource_path


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture()
def ledger() -> Iterator[ResearchLedger]:
    store = ResearchLedger(":memory:")
    try:
        yield store
    finally:
        store.close()


def _characterize_control(store: ResearchLedger) -> None:
    """Record the characterized control and the defeat attempt — generic, unnamed.

    The surface is covered with the bypass work and its outcome; the defeat
    attempt is captured as re-executable evidence. Neither names a specific
    control or technique.
    """
    store.record_coverage_cell(
        CoverageCell(
            id="cov-bypass",
            surface="the surface behind the control",
            risk_area="a control blocking the current primitive",
            outcome="reported",
            evidence="characterized the control, then defeated it",
            approaches_tried=["characterize the control", "defeat attempt", "validate the bypass"],
            agent_id="bypasser-1",
        )
    )
    store.record_evidence(
        Evidence(
            id="e-bypass",
            kind="proxy_exchange",
            evidence_refs=["77"],
            replay=EvidenceReplay(
                medium="http",
                inputs={"method": "GET", "url": "http://synthetic.invalid/behind-control"},
            ),
            summary="the defeat attempt against the control",
        )
    )


# ── role wiring (mirrors the 2.2 reviewer role) ──────────────────────────────


def test_bypassing_contract_renders_and_surfaces_every_requirement() -> None:
    contract = render_contract("bypassing")
    assert "## CONTRACT (generated" in contract
    assert missing_requirements(contract, role_requirements("bypassing")) == []
    # The bypassing discipline is surfaced, class-agnostically.
    assert "Characterize-then-defeat" in contract
    assert "validator path" in contract
    assert "The surface is not abandoned" in contract


def test_bypassing_owned_tools_are_all_real() -> None:
    assert set(ROLE_TOOLS["bypassing"]) <= registered_tool_names()
    for tool in ("get_threat_model", "amend_threat_model", "record_coverage",
                 "create_vulnerability_report", "agent_finish"):
        assert tool in render_contract("bypassing")


def test_bypassing_persona_resolves_from_the_role() -> None:
    assert _role_persona_for("anything", [], role="bypassing") == (
        _BYPASSING_PERSONA,
        "role:bypassing",
    )
    assert "bypassing" in _PERSONA_REQUIRED_ROLES


def test_bypassing_persona_file_is_method_only() -> None:
    body = (get_zen_resource_path("skills") / "coordination" / "bypassing_agent.md").read_text(
        encoding="utf-8"
    )
    assert "Bypassing Agent — Method" in body
    assert "## CONTRACT (generated" not in body
    assert render_contract("bypassing") not in body


def test_rendered_bypassing_prompt_is_method_plus_generated_contract() -> None:
    prompt = render_system_prompt(
        skills=["coordination/bypassing_agent"], is_root=False, scan_mode="deep"
    )
    assert "Bypassing Agent — Method" in prompt
    assert "## CONTRACT (generated" in prompt


# ── characterize-and-defeat (not abandon) over the §2.2 socket ───────────────


def test_bypassing_characterizes_and_defeats_the_control_advancing_the_primitive(
    ledger: ResearchLedger,
) -> None:
    # A primitive blocked by a control.
    ledger.record_evidence(
        Evidence(id="e-block", kind="proxy_exchange", evidence_refs=["70"])
    )
    ledger.record_finding(Finding(id="fb", state="blocked", evidence_ids=["e-block"]))

    # The bypassing agent characterizes the control and records the defeat attempt
    # — the surface is covered, not abandoned.
    _characterize_control(ledger)
    assert any(c.id == "cov-bypass" for c in ledger.get_coverage_cells())
    assert ledger.get_evidence("e-bypass") is not None

    # The defeated control is evidence that advances the blocked primitive: it is
    # confirmed through the SAME validator socket, not because the surface was
    # reached again.
    ledger.confirm_finding(
        "fb",
        ValidatorVerdict(
            id="vd-bypass", finding_id="fb", oracle="effect_observed", passed=True,
            reach_only=False, author="reviewer-1", oracle_signal={"effect": "fired with bypass"},
            replayed_evidence_ids=["e-bypass"],
        ),
    )
    confirmed = ledger.get_finding("fb")
    assert confirmed is not None
    assert confirmed.state == "confirmed"  # the control was defeated; the primitive advanced
    assert confirmed.validator_verdict_id == "vd-bypass"


def test_a_reach_only_bypass_does_not_confirm_but_the_surface_is_not_abandoned(
    ledger: ResearchLedger,
) -> None:
    ledger.record_finding(Finding(id="fb2", state="blocked"))
    _characterize_control(ledger)

    # A bypass that only reached the surface again (no re-observed effect) is a
    # reach-only verdict — it cannot confirm, exactly as reaching never completes
    # a chain hop.
    reach_only = ValidatorVerdict(
        id="vd-reach", finding_id="fb2", oracle="effect_observed", passed=False,
        reach_only=True, author="reviewer-1", oracle_signal={},
    )
    with pytest.raises(VerdictError):
        ledger.confirm_finding("fb2", reach_only)

    # The primitive stays unconfirmed — but the control was characterized and the
    # attempt recorded, so the surface is not silently abandoned.
    assert ledger.get_finding("fb2").state == "blocked"
    assert any(c.id == "cov-bypass" for c in ledger.get_coverage_cells())
