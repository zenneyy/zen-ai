"""Parallel-discovery fan-out, effort-scaling, and the unscoped budget (item 2.3).

Discovery is the breadth-parallel half of the hunting topology. These exercise the
pure enumeration and allocation logic:

* cells are drawn from the 1.5 architecture-implied-classes enumeration paired with
  the ledger's typed surfaces, and split into **independent** cells (dispatchable
  in parallel now) and **dependent** cells (routed to chaining because their
  surface is reached only through a component);
* the effort-scaling rule scales the parallel-hunter count to the surface size by
  an explicit, bounded rule — small→few, larger→more, capped — and is auditable;
* the unscoped-exploration budget is explicit, bounded, and always reserves at
  least a minimum so investigation is never fully confined to the enumerated grid.

Everything here is class-agnostic: the fixture is a synthetic two-stage path and
the assertions are over counts and reachability, never a particular class.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from zen.tools.hunt_topology.discovery import (
    DiscoveryCell,
    dependent_cells,
    discovery_cells,
    discovery_hunter_allocation,
    independent_cells,
    is_unscoped_surface,
    plan_discovery,
    unscoped_exploration_budget,
)
from zen.tools.ledger.objects import Finding, ValidatorVerdict
from zen.tools.ledger.projection import surfaces_from_hops
from zen.tools.ledger.store import ResearchLedger
from zen.tools.threat_model.implied_classes import implied_classes


if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture()
def ledger() -> Iterator[ResearchLedger]:
    store = ResearchLedger(":memory:")
    try:
        yield store
    finally:
        store.close()


# A synthetic two-stage path: a primary application in front of a durable store
# reached only through it. No transforming front, so the fixture implies classes
# off two component kinds and the trust-transition boundary between them.
_HOPS = [
    {"name": "app", "role": "application framework"},
    {"name": "store", "role": "data store"},
]
_ARCH = {"t": _HOPS}


def _surfaces() -> list:
    return surfaces_from_hops("t", _HOPS)


# ── cells are drawn from implied classes × typed surfaces ────────────────────


def test_cells_cover_every_implied_class_and_dedup() -> None:
    surfaces = _surfaces()
    cells = discovery_cells(_ARCH, surfaces)
    assert cells, "a non-empty architecture must yield discovery cells"
    # Every implied class (the 1.5 enumeration, reused not re-derived) is covered
    # by at least one cell, so no implied class is dropped from the fan-out.
    assert {c.vuln_class for c in cells} == set(implied_classes(_ARCH))
    # Cells are hashable and deduplicated — two hunters never get the same cell.
    assert len(set(cells)) == len(cells)


def test_cells_are_grounded_on_the_typed_surfaces() -> None:
    surfaces = _surfaces()
    cells = discovery_cells(_ARCH, surfaces)
    surface_ids = {s.id for s in surfaces}
    # Every bound cell names a real surface; the fixture binds all of them.
    assert all(c.surface_id in surface_ids for c in cells)


# ── independent vs dependent (the dispatch split) ────────────────────────────


def test_independent_and_dependent_cells_partition_on_reachability() -> None:
    surfaces = _surfaces()
    cells = discovery_cells(_ARCH, surfaces)
    independent = independent_cells(cells)
    dependent = dependent_cells(cells)

    # The two halves partition the cells.
    assert len(independent) + len(dependent) == len(cells)
    assert set(independent).isdisjoint(set(dependent))

    # Independence is the reachability signal: a dependent cell's surface is
    # reached only through a component (a chaining dependency), never independent.
    assert all(c.reachability != "reached_through_component" for c in independent)
    assert all(c.reachability == "reached_through_component" for c in dependent)

    # The fixture exercises both halves: the app surface is publicly reachable
    # (independent), the store behind it is reached through a component (dependent).
    assert independent, "the publicly-reachable surface yields independent cells"
    assert dependent, "the component-reached surface yields chaining-dependency cells"


def test_independent_cells_do_not_depend_on_another_cells_output() -> None:
    """Independent cells are self-contained at dispatch — no cell references another."""
    surfaces = _surfaces()
    independent = independent_cells(discovery_cells(_ARCH, surfaces))
    # A discovery cell carries only its own class and surface; it cannot encode a
    # dependency on another cell's confirmed primitive, so two independent cells
    # are dispatchable without ordering between them.
    for cell in independent:
        assert isinstance(cell, DiscoveryCell)
        assert cell.vuln_class and cell.surface_id


# ── effort-scaling rule (bounded, monotonic, auditable) ──────────────────────


def test_allocation_scales_small_to_few_large_to_capped() -> None:
    # Nothing to discover -> no hunters.
    assert discovery_hunter_allocation(0, 0) == 0
    # A small surface earns few hunters.
    assert discovery_hunter_allocation(1, 1) == 1
    # A moderate surface earns more.
    assert discovery_hunter_allocation(5, 5) == 5
    # A large surface is bounded by the hard ceiling (no sprawl).
    big = discovery_hunter_allocation(100, 100)
    assert big == 12
    assert discovery_hunter_allocation(1000, 1000) == big


def test_allocation_is_monotonic_non_decreasing_and_bounded() -> None:
    counts = [discovery_hunter_allocation(n, n) for n in range(0, 40)]
    assert counts == sorted(counts)  # non-decreasing in surface size
    assert all(0 <= c <= 12 for c in counts)
    # A fixed, deterministic rule: same inputs, same output (auditable).
    assert discovery_hunter_allocation(7, 4) == discovery_hunter_allocation(7, 4)


# ── unscoped-exploration budget (explicit, bounded, always reserved) ─────────


def test_unscoped_budget_is_bounded_and_always_reserved() -> None:
    # Always at least a minimum, even when no cells were enumerated — then
    # unscoped exploration matters most.
    assert unscoped_exploration_budget(0) >= 1
    # Scales with discovery effort, up to a small cap (never the whole run).
    assert unscoped_exploration_budget(4) >= 1
    assert unscoped_exploration_budget(12) == 3
    assert unscoped_exploration_budget(1000) == 3
    budgets = [unscoped_exploration_budget(n) for n in range(0, 40)]
    assert budgets == sorted(budgets)
    assert all(1 <= b <= 3 for b in budgets)


def test_unscoped_surface_is_outside_the_enumerated_cells() -> None:
    cells = discovery_cells(_ARCH, _surfaces())
    # A surface that is in a cell is scoped; one that is not is unscoped — a
    # finding on it originated from unscoped exploration but flows into the same
    # ledger and confirmation path.
    scoped_surface = next(c.surface_id for c in cells if c.surface_id)
    assert is_unscoped_surface(scoped_surface, cells) is False
    assert is_unscoped_surface("t#999-never-enumerated", cells) is True


def test_an_unscoped_finding_flows_through_the_same_ledger_path(ledger: ResearchLedger) -> None:
    """A finding from unscoped exploration uses the same record+confirm path.

    The budget reserves unscoped exploration; a finding it yields on a surface
    outside every enumerated cell is a first-class finding, confirmed through the
    same section-2.2 socket as any cell-scoped finding — no separate path.
    """
    cells = discovery_cells(_ARCH, _surfaces())
    unscoped_surface = "t#999-never-enumerated"
    assert is_unscoped_surface(unscoped_surface, cells) is True

    ledger.record_finding(Finding(id="f_unscoped", state="open"))
    ledger.confirm_finding(
        "f_unscoped",
        ValidatorVerdict(
            id="vd-unscoped", finding_id="f_unscoped", oracle="effect_observed", passed=True,
            reach_only=False, author="reviewer-1", oracle_signal={"effect": "re-observed"},
        ),
    )
    confirmed = ledger.get_finding("f_unscoped")
    assert confirmed is not None
    assert confirmed.state == "confirmed"


# ── the auditable allocation record ──────────────────────────────────────────


def test_plan_discovery_is_consistent_and_recordable() -> None:
    allocation = plan_discovery(_ARCH, _surfaces())
    # The counts are internally consistent.
    assert allocation.total_cells == allocation.independent_cells + allocation.dependent_cells
    assert 0 <= allocation.discovery_hunters <= 12
    assert 1 <= allocation.unscoped_budget <= 3
    # It is flat and recordable (the body of an auditable note), not an opaque
    # constant — the orchestration decision can be reproduced from the inventory.
    record = allocation.as_record()
    assert record["total_cells"] == allocation.total_cells
    assert record["discovery_hunters"] == allocation.discovery_hunters
    assert record["unscoped_budget"] == allocation.unscoped_budget
    # Deterministic: same inventory, same allocation.
    assert plan_discovery(_ARCH, _surfaces()).as_record() == record
