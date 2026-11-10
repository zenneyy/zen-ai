"""The chaining agent as a first-class role + its two gates (Phase 2, item 2.3).

The chaining agent reuses the Phase-1 role + generated-CONTRACT machinery (as the
reviewer did in 2.2) and adds the review's chain-decomposition forcing function:

* **per-hop distinct-class decomposition** — every hop, *including the terminal
  hop*, enumerates its own distinct candidate primitive and the class it belongs
  to; a plan that collapses distinct-class hops into one framing or omits the
  terminal hop is rejected before composition. The gate is generic (it checks
  presence and distinctness, never which class appears);
* **confirmed-primitive advancement** — a hop advances only when its intended
  primitive is a confirmed finding (the section-2.2 socket), never because a
  surface was reached.

Everything here is class-agnostic: hops carry synthetic class labels and generic
primitive descriptions, so the gate is exercised without privileging any class.
"""

from __future__ import annotations

import json
import threading
from typing import TYPE_CHECKING

import pytest
from agents.tool_context import ToolContext

from zen.agents.contract import (
    ROLE_TOOLS,
    missing_requirements,
    registered_tool_names,
    render_contract,
    role_requirements,
)
from zen.agents.prompt import render_system_prompt
from zen.tools.agents_graph.tools import (
    _CHAINING_PERSONA,
    _PERSONA_REQUIRED_ROLES,
    _role_persona_for,
)
from zen.tools.hunt_topology.chains import (
    ChainDecompositionError,
    assert_decomposition_complete,
    chain_claimable,
    chain_reaches_objective,
    claimable_depth,
    decomposition_complete,
    decomposition_problems,
    hop_confirmed,
)
from zen.tools.hunt_topology.discovery import (
    dependent_cells,
    discovery_cells,
    independent_cells,
)
from zen.tools.hunt_topology.tools import record_chain_plan
from zen.tools.ledger.objects import (
    ChainHop,
    ChainPlan,
    Evidence,
    EvidenceReplay,
    Finding,
    ValidatorVerdict,
)
from zen.tools.ledger.runtime import set_ledger
from zen.tools.ledger.store import ResearchLedger
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


def _passing_verdict(finding_id: str) -> ValidatorVerdict:
    return ValidatorVerdict(
        id=f"vd-{finding_id}",
        finding_id=finding_id,
        oracle="effect_observed",
        passed=True,
        reach_only=False,
        author="reviewer-1",
        oracle_signal={"effect": "re-observed"},
    )


def _record_confirmed(store: ResearchLedger, finding_id: str) -> None:
    store.record_finding(Finding(id=finding_id, state="open"))
    store.confirm_finding(finding_id, _passing_verdict(finding_id))


def _hop(index: int, primitive: str, cls: str, *, terminal: bool = False,
         finding_id: str = "", surface: str = "") -> ChainHop:
    return ChainHop(
        index=index,
        target_surface=surface or f"s#{index}",
        candidate_class=cls,
        candidate_primitive=primitive,
        terminal=terminal,
        finding_id=finding_id,
    )


def _decomposed_plan(finding_0: str = "", finding_1: str = "") -> ChainPlan:
    """A well-decomposed two-hop plan: distinct primitive + class per hop."""
    return ChainPlan(
        id="chain-ok",
        impact_objective="chained",
        hops=[
            _hop(0, "enabling primitive on the entry surface", "class_a", finding_id=finding_0),
            _hop(1, "distinct terminal primitive", "class_b", terminal=True, finding_id=finding_1),
        ],
    )


# ── role wiring (mirrors the 2.2 reviewer role) ──────────────────────────────


def test_chaining_contract_renders_and_surfaces_every_requirement() -> None:
    contract = render_contract("chaining")
    assert "## CONTRACT (generated" in contract
    assert missing_requirements(contract, role_requirements("chaining")) == []
    # The chaining disciplines are surfaced, class-agnostically.
    assert "Per-hop distinct-class decomposition" in contract
    assert "Confirmed-primitive advancement" in contract
    assert "Single long-lived context" in contract


def test_chaining_owned_tools_are_all_real() -> None:
    assert set(ROLE_TOOLS["chaining"]) <= registered_tool_names()
    for tool in ("record_chain_plan", "get_threat_model", "create_vulnerability_report",
                 "agent_finish"):
        assert tool in render_contract("chaining")


def test_chaining_persona_resolves_from_the_role() -> None:
    assert _role_persona_for("anything", [], role="chaining") == (
        _CHAINING_PERSONA,
        "role:chaining",
    )
    assert "chaining" in _PERSONA_REQUIRED_ROLES


def test_chaining_persona_file_is_method_only() -> None:
    body = (get_zen_resource_path("skills") / "coordination" / "chaining_agent.md").read_text(
        encoding="utf-8"
    )
    assert "Chaining Agent — Method" in body
    assert "## CONTRACT (generated" not in body
    assert render_contract("chaining") not in body


def test_rendered_chaining_prompt_is_method_plus_generated_contract() -> None:
    prompt = render_system_prompt(
        skills=["coordination/chaining_agent"], is_root=False, scan_mode="deep"
    )
    assert "Chaining Agent — Method" in prompt
    assert "## CONTRACT (generated" in prompt


# ── the per-hop distinct-class decomposition gate (the F5 fix) ───────────────


def test_a_fully_decomposed_plan_passes_the_gate() -> None:
    plan = _decomposed_plan()
    assert decomposition_problems(plan) == []
    assert decomposition_complete(plan) is True
    assert_decomposition_complete(plan)  # does not raise


def test_a_plan_with_no_terminal_hop_is_rejected() -> None:
    """Modelling the whole chain through the enabling framing under-models the
    terminal hop — the plan reaches for the objective with no terminal hop."""
    collapsed = ChainPlan(
        id="no-terminal",
        impact_objective="chained",
        hops=[_hop(0, "the single enabling primitive", "class_a")],
    )
    problems = decomposition_problems(collapsed)
    assert problems
    assert any("terminal" in p for p in problems)
    assert decomposition_complete(collapsed) is False
    with pytest.raises(ChainDecompositionError):
        assert_decomposition_complete(collapsed)


def test_a_terminal_hop_that_reuses_an_earlier_primitive_is_rejected() -> None:
    """The collapse signature: the terminal hop merely restates the framing
    primitive instead of enumerating its own distinct one."""
    collapsed = ChainPlan(
        id="collapsed",
        impact_objective="chained",
        hops=[
            _hop(0, "the same framing primitive", "class_a"),
            _hop(1, "the same framing primitive", "class_a", terminal=True),
        ],
    )
    problems = decomposition_problems(collapsed)
    assert any("reuses" in p for p in problems)
    assert decomposition_complete(collapsed) is False


def test_a_hop_missing_its_class_or_primitive_is_rejected() -> None:
    missing_class = ChainPlan(
        id="mc",
        impact_objective="chained",
        hops=[
            _hop(0, "p0", ""),
            _hop(1, "p1", "class_b", terminal=True),
        ],
    )
    assert any("candidate_class" in p for p in decomposition_problems(missing_class))

    missing_primitive = ChainPlan(
        id="mp",
        impact_objective="chained",
        hops=[
            _hop(0, "p0", "class_a"),
            _hop(1, "", "class_b", terminal=True),
        ],
    )
    assert any("candidate_primitive" in p for p in decomposition_problems(missing_primitive))


def test_an_empty_plan_is_rejected() -> None:
    assert decomposition_complete(ChainPlan(id="e", impact_objective="chained", hops=[])) is False


def test_the_gate_is_generic_not_tied_to_any_class_sequence() -> None:
    """A distinct candidate primitive and class per hop passes for ANY class
    labels — the gate checks presence and distinctness, never which class appears
    or in what order."""
    for first, second in (("class_a", "class_b"), ("plugh", "xyzzy"), ("q", "z")):
        plan = ChainPlan(
            id="generic",
            impact_objective="weaponized",
            hops=[
                _hop(0, "first distinct primitive", first),
                _hop(1, "second distinct primitive", second, terminal=True),
            ],
        )
        assert decomposition_complete(plan) is True


def test_record_chain_enforces_the_decomposition_gate(ledger: ResearchLedger) -> None:
    collapsed = ChainPlan(
        id="c",
        impact_objective="chained",
        hops=[_hop(0, "the single enabling primitive", "class_a")],
    )
    with pytest.raises(ChainDecompositionError):
        ledger.record_chain(collapsed)
    assert ledger.get_chain("c") is None  # a rejected plan is never recorded

    recorded = ledger.record_chain(_decomposed_plan())
    assert recorded.id == "chain-ok"
    stored = ledger.get_chain("chain-ok")
    assert stored is not None
    assert [h.candidate_class for h in stored.hops] == ["class_a", "class_b"]


@pytest.mark.asyncio
async def test_record_chain_plan_tool_rejects_collapsed_accepts_decomposed() -> None:
    ctx = ToolContext(
        context={"agent_id": "chainer-1"},
        tool_name=record_chain_plan.name,
        tool_call_id="c1",
        tool_arguments="{}",
    )

    collapsed = {
        "id": "c",
        "impact_objective": "chained",
        "hops": [
            {"index": 0, "target_surface": "s#0", "candidate_class": "class_a",
             "candidate_primitive": "the single enabling primitive", "terminal": False}
        ],
    }
    raw = await record_chain_plan.on_invoke_tool(
        ctx, json.dumps({"chain_plan": json.dumps(collapsed)})
    )
    res = json.loads(raw)
    assert res["success"] is False
    assert res["decomposition_problems"]
    assert "hops:" in res["error"]

    decomposed = {
        "id": "c2",
        "impact_objective": "chained",
        "hops": [
            {"index": 0, "target_surface": "s#0", "candidate_class": "class_a",
             "candidate_primitive": "enabling primitive", "terminal": False},
            {"index": 1, "target_surface": "s#1", "candidate_class": "class_b",
             "candidate_primitive": "distinct terminal primitive", "terminal": True},
        ],
    }
    raw2 = await record_chain_plan.on_invoke_tool(
        ctx, json.dumps({"chain_plan": json.dumps(decomposed)})
    )
    res2 = json.loads(raw2)
    assert res2["success"] is True
    assert res2["decomposition"] == "complete"
    assert res2["hops"] == 2


@pytest.mark.asyncio
async def test_record_chain_plan_tool_records_and_reports_advancement(
    ledger: ResearchLedger,
) -> None:
    """The tool records the chain to the ledger and reports advancement from it.

    With a live ledger: a decomposed plan is recorded (reusing the 2.1 typed
    object), and the response reports how far it is claimable, read back from each
    hop's confirmed finding — hop 0 confirmed, hop 1 not.
    """
    set_ledger(ledger)
    try:
        _record_confirmed(ledger, "f0")
        ledger.record_finding(Finding(id="f1", state="open"))
        ctx = ToolContext(
            context={"agent_id": "chainer-1"},
            tool_name=record_chain_plan.name,
            tool_call_id="c1",
            tool_arguments="{}",
        )
        plan = {
            "id": "chain-live",
            "impact_objective": "chained",
            "hops": [
                {"index": 0, "target_surface": "s#0", "candidate_class": "class_a",
                 "candidate_primitive": "enabling primitive", "terminal": False,
                 "finding_id": "f0"},
                {"index": 1, "target_surface": "s#1", "candidate_class": "class_b",
                 "candidate_primitive": "distinct terminal primitive", "terminal": True,
                 "finding_id": "f1"},
            ],
        }
        raw = await record_chain_plan.on_invoke_tool(
            ctx, json.dumps({"chain_plan": json.dumps(plan)})
        )
        res = json.loads(raw)

        assert res["success"] is True
        assert res["recorded"] is True
        # Recorded to the ledger (the 2.1 typed object), not a parallel store.
        assert ledger.get_chain("chain-live") is not None
        # Advancement read back from the confirmed findings: hop 0 confirmed, hop 1 not.
        assert res["claimable_depth"] == 1
        assert res["chain_claimable"] is False
        assert [hop["index"] for hop in res["blocking_hops"]] == [1]
    finally:
        set_ledger(None)


# ── confirmed-primitive advancement (reach ≠ perform) ────────────────────────


def test_hop_advances_only_on_a_confirmed_primitive_not_on_reach(
    ledger: ResearchLedger,
) -> None:
    # The hop's finding carries evidence that the surface was REACHED, but no
    # passing verdict — so it is not confirmed. Reaching is not performing.
    ledger.record_evidence(
        Evidence(
            id="e1",
            kind="proxy_exchange",
            evidence_refs=["42"],
            replay=EvidenceReplay(
                medium="http", inputs={"method": "GET", "url": "http://synthetic.invalid/x"}
            ),
        )
    )
    ledger.record_finding(Finding(id="f1", state="open", evidence_ids=["e1"]))
    hop = _hop(0, "terminal primitive", "class_b", terminal=True, finding_id="f1")
    plan = ChainPlan(id="reach", impact_objective="weaponized", hops=[hop])

    # Reached the surface (evidence captured), but the primitive is unconfirmed:
    # the hop does not advance, and the chain is not claimable.
    assert hop_confirmed(hop, ledger) is False
    assert chain_claimable(plan, ledger) is False

    # The same hop, once its finding is confirmed via a passing verdict (the
    # section-2.2 socket), advances.
    ledger.confirm_finding(
        "f1",
        ValidatorVerdict(
            id="vd-1", finding_id="f1", oracle="effect_observed", passed=True,
            reach_only=False, author="rev-1", oracle_signal={"effect": "x"},
            replayed_evidence_ids=["e1"],
        ),
    )
    assert hop_confirmed(hop, ledger) is True
    assert chain_claimable(plan, ledger) is True


def test_claimable_depth_stops_at_the_first_unconfirmed_hop(ledger: ResearchLedger) -> None:
    _record_confirmed(ledger, "f0")
    ledger.record_finding(Finding(id="f1", state="open"))  # unconfirmed
    plan = _decomposed_plan(finding_0="f0", finding_1="f1")

    # Decomposed, hop 0 confirmed, hop 1 not: claimable only to depth 1.
    assert decomposition_complete(plan) is True
    assert claimable_depth(plan, ledger) == 1
    assert chain_claimable(plan, ledger) is False
    assert chain_reaches_objective(plan, ledger) is False

    _record_confirmed_existing(ledger, "f1")
    assert claimable_depth(plan, ledger) == 2
    assert chain_claimable(plan, ledger) is True


def _record_confirmed_existing(store: ResearchLedger, finding_id: str) -> None:
    store.confirm_finding(finding_id, _passing_verdict(finding_id))


# ── multi-step succeeds where single-step fails (composition earns its cost) ──


def test_multi_step_objective_succeeds_through_composition_where_single_step_fails(
    ledger: ResearchLedger,
) -> None:
    # Two-stage path: an entry surface and a terminal surface reached only through
    # it. The fixture is synthetic; no scenario is named.
    arch_hops = [
        {"name": "entry", "role": "application framework"},
        {"name": "back", "role": "data store"},
    ]
    surfaces = ledger.record_architecture("t", arch_hops)
    by_name = {s.name: s for s in surfaces}
    entry_id = by_name["entry"].id
    back_id = by_name["back"].id

    # The terminal surface is a CHAINING DEPENDENCY, not an independent discovery
    # cell — so independent single-step discovery never confirms the terminal
    # primitive on its own.
    cells = discovery_cells({"t": arch_hops}, surfaces)
    independent_surface_ids = {c.surface_id for c in independent_cells(cells)}
    dependent_surface_ids = {c.surface_id for c in dependent_cells(cells)}
    assert entry_id in independent_surface_ids
    assert back_id in dependent_surface_ids
    assert back_id not in independent_surface_ids

    # Independent single-step work confirms the enabling primitive on the entry
    # surface only; the terminal primitive stays unconfirmed.
    _record_confirmed(ledger, "f_entry")
    ledger.record_finding(Finding(id="f_term", state="open"))

    plan = ChainPlan(
        id="composed",
        impact_objective="chained",
        hops=[
            _hop(0, "enabling primitive", "class_a", finding_id="f_entry", surface=entry_id),
            _hop(1, "distinct terminal primitive", "class_b", terminal=True,
                 finding_id="f_term", surface=back_id),
        ],
    )

    # Fully decomposed, but the terminal is unconfirmed: the composed objective is
    # NOT reached. This is exactly where independent single-step work stalls.
    assert decomposition_complete(plan) is True
    assert chain_reaches_objective(plan, ledger) is False

    # The chaining agent drives the dependent terminal hop to a confirmed verdict —
    # the composition it alone performs — and the objective is reached.
    _record_confirmed_existing(ledger, "f_term")
    assert chain_reaches_objective(plan, ledger) is True


# ── single long-lived context ────────────────────────────────────────────────


def test_chaining_is_one_long_lived_context_holding_the_full_hop_vector() -> None:
    body = (get_zen_resource_path("skills") / "coordination" / "chaining_agent.md").read_text(
        encoding="utf-8"
    )
    # The persona commits to one long-lived context, not per-hop fragments.
    assert "one long-lived context" in body.lower()
    assert "Single long-lived context" in render_contract("chaining")
    # Structurally, one ChainPlan holds the entire ordered hop vector — the whole
    # composition lives in one record, never scattered across fragments.
    plan = _decomposed_plan()
    assert [h.index for h in plan.hops] == [0, 1]
    assert sum(1 for h in plan.hops if h.terminal) == 1


def test_parallel_discovery_writes_do_not_collide(ledger: ResearchLedger) -> None:
    """Two hunters on different cells produce non-conflicting ledger events.

    Different findings are distinct ledger objects, so concurrent appends are
    serialised and none is lost — the append-only guarantee the fan-out relies on.
    """

    def write(i: int) -> None:
        ledger.record_finding(Finding(id=f"f{i}", state="open"))

    threads = [threading.Thread(target=write, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert {f.id for f in ledger.list_findings()} == {f"f{i}" for i in range(8)}
