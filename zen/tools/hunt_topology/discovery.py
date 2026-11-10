"""Parallel-discovery fan-out: independent class×surface cells (Phase 2, item 2.3).

Discovery is the breadth-parallel half of the hunting topology. Root fans out
hunters across **independent** cells — each a (candidate vulnerability class ×
:class:`~zen.tools.ledger.objects.SurfaceNode`) pair — drawn from two sources the
engine already owns, not re-derived here:

* the **architecture-implied-classes enumeration** of item 1.5
  (:func:`zen.tools.threat_model.implied_classes.implied_classes`) — the classes
  the structure implies, each tagged with the component or boundary that implied
  it; and
* the **ledger's typed surfaces** (item 2.1) — the reachable points, each carrying
  the ``reachability`` the projection computed.

A cell is **independent at dispatch** when its surface is reachable without first
establishing another cell's confirmed primitive. The structural proxy is the
surface's ``reachability``: a ``publicly_reachable`` surface can be hunted
immediately, while a ``reached_through_component`` surface is reachable only
*through* another component's behavior — so a cell on it depends on a prior
primitive and is routed to the chaining phase, not dispatched as discovery.

The effort-scaling rule and the unscoped-exploration budget are here too, as pure
functions of the surface inventory and the cell count, so the chosen allocation is
deterministic and auditable rather than a fixed constant.

Everything here is class-agnostic: catalog class slugs are data; nothing
privileges a class, technique, scenario, or target shape.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import TYPE_CHECKING

from zen.tools.threat_model.implied_classes import implied_classes


if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping, Sequence

    from zen.tools.ledger.objects import SurfaceNode


__all__ = [
    "DISCOVERY_FANOUT_DESCRIPTION",
    "EFFORT_SCALING_DESCRIPTION",
    "UNSCOPED_EXPLORATION_DESCRIPTION",
    "DiscoveryAllocation",
    "DiscoveryCell",
    "dependent_cells",
    "discovery_cells",
    "discovery_hunter_allocation",
    "independent_cells",
    "is_unscoped_surface",
    "plan_discovery",
    "unscoped_exploration_budget",
]


# How a cell's surface is reached, mirrored from the ledger's Reachability so the
# split does not re-import the enum. A surface reached only through a component is
# a chaining dependency, never an independent discovery cell.
_DEPENDENT_REACHABILITY = "reached_through_component"
_BOUNDARY_PREFIX = "boundary "
_BOUNDARY_SEP = " <-> "


@dataclass(frozen=True)
class DiscoveryCell:
    """One (candidate class × surface) discovery cell — an independent hunt unit.

    Frozen (hashable) so a set of cells deduplicates and two cells can be compared
    for independence. A cell bundles the class the architecture implied, the typed
    surface it is grounded on, that surface's reachability (the independence
    signal), and the structure that implied the class (for the audit trail).
    """

    vuln_class: str
    """The candidate vulnerability class for this cell, a catalog slug used as
    data — never privileged, never the subject of a class-specific rule."""

    surface_id: str
    """The :class:`~zen.tools.ledger.objects.SurfaceNode` id this cell is grounded
    on. Empty when the implying structure named no mapped surface — the class is
    still a discovery target, just not yet bound to a typed surface."""

    surface_name: str
    """The surface's label (or the implying structure's name when unbound)."""

    reachability: str
    """The surface's reachability — the independence signal. A
    ``reached_through_component`` cell is a chaining dependency, not independent."""

    implied_by: str
    """The component or boundary that implied this cell's class (item 1.5's
    reason source) — so the cell's provenance back to the structure is auditable."""


def _surfaces_by_name(surfaces: Iterable[SurfaceNode]) -> dict[str, list[SurfaceNode]]:
    by_name: dict[str, list[SurfaceNode]] = {}
    for node in surfaces:
        key = (node.name or "").strip()
        if key:
            by_name.setdefault(key, []).append(node)
    return by_name


def _sources_for(reason_source: str) -> list[str]:
    """The component name(s) a reason source names — one, or both sides of a boundary."""
    if reason_source.startswith(_BOUNDARY_PREFIX):
        label = reason_source[len(_BOUNDARY_PREFIX) :]
        return [part.strip() for part in label.split(_BOUNDARY_SEP) if part.strip()]
    return [reason_source.strip()] if reason_source.strip() else []


def discovery_cells(
    architecture: Mapping[str, Sequence[Mapping[str, str]]],
    surfaces: Iterable[SurfaceNode],
) -> list[DiscoveryCell]:
    """Enumerate the (implied class × surface) discovery cells for a target.

    Reuses item 1.5's :func:`implied_classes` for the class set (never a
    re-derived list) and binds each implied class to the ledger surface(s) the
    implying structure named. A class implied by a boundary binds to both adjacent
    surfaces; a class whose implying structure names no mapped surface yields one
    unbound cell, so every implied class still becomes at least one cell (and
    therefore a hunter or a reasoned dismissal downstream). Deduplicated and
    ordered by (class, surface).
    """
    surface_list = list(surfaces)
    by_name = _surfaces_by_name(surface_list)
    implied = implied_classes(architecture)

    cells: dict[tuple[str, str], DiscoveryCell] = {}
    for vuln_class, reason in implied.items():
        matched: list[SurfaceNode] = []
        for source in _sources_for(reason.source):
            matched.extend(by_name.get(source, []))
        if matched:
            for node in matched:
                key = (vuln_class, node.id)
                cells.setdefault(
                    key,
                    DiscoveryCell(
                        vuln_class=vuln_class,
                        surface_id=node.id,
                        surface_name=node.name or node.id,
                        reachability=node.reachability,
                        implied_by=reason.source,
                    ),
                )
        else:
            key = (vuln_class, "")
            cells.setdefault(
                key,
                DiscoveryCell(
                    vuln_class=vuln_class,
                    surface_id="",
                    surface_name=reason.source,
                    reachability="unknown",
                    implied_by=reason.source,
                ),
            )
    return [cells[key] for key in sorted(cells)]


def independent_cells(cells: Iterable[DiscoveryCell]) -> list[DiscoveryCell]:
    """The cells dispatchable in parallel immediately — not chaining dependencies.

    A cell is independent at dispatch when its surface does not require another
    cell's confirmed primitive to be reached: every reachability except
    ``reached_through_component``. These are the cells root fans parallel discovery
    hunters across.
    """
    return [c for c in cells if c.reachability != _DEPENDENT_REACHABILITY]


def dependent_cells(cells: Iterable[DiscoveryCell]) -> list[DiscoveryCell]:
    """The cells whose surface is reached only through a component — chaining work.

    A candidate primitive whose investigation depends on first reaching its
    surface through another component is not a discovery cell; it is routed to the
    chaining phase, where the reach is a prior hop.
    """
    return [c for c in cells if c.reachability == _DEPENDENT_REACHABILITY]


# ── effort-scaling rule (data-driven, bounded, auditable) ─────────────────────

_DEFAULT_CELLS_PER_HUNTER = 1
_MIN_DISCOVERY_HUNTERS = 1
_SOFT_MAX_DISCOVERY_HUNTERS = 8
_HARD_MAX_DISCOVERY_HUNTERS = 12


def discovery_hunter_allocation(
    cell_count: int,
    surface_count: int = 0,
    *,
    cells_per_hunter: int = _DEFAULT_CELLS_PER_HUNTER,
    min_hunters: int = _MIN_DISCOVERY_HUNTERS,
    soft_max_hunters: int = _SOFT_MAX_DISCOVERY_HUNTERS,
    hard_max_hunters: int = _HARD_MAX_DISCOVERY_HUNTERS,
) -> int:
    """How many parallel discovery hunters to spawn, from the surface inventory.

    Data-driven, not a fixed constant: the target count grows with the number of
    independent cells, and the cap is lifted toward a hard ceiling for a target
    with a genuinely large surface inventory — so the system neither sprawls
    (unbounded spawns) nor under-staffs (one hunter for a large surface). Zero
    cells means nothing to discover, so zero hunters. Monotonic non-decreasing in
    ``cell_count`` and bounded in ``[min_hunters, hard_max_hunters]``.
    """
    if cell_count <= 0:
        return 0
    per_hunter = max(1, cells_per_hunter)
    target = math.ceil(cell_count / per_hunter)
    # A larger surface inventory lifts the soft cap toward the hard ceiling; a
    # small surface stays tight on the soft cap.
    cap = min(hard_max_hunters, max(soft_max_hunters, surface_count))
    return max(min_hunters, min(target, cap))


# ── unscoped-exploration budget (bounded; never the whole run) ────────────────

_UNSCOPED_FRACTION = 0.25
_MIN_UNSCOPED = 1
_MAX_UNSCOPED = 3


def unscoped_exploration_budget(
    discovery_hunters: int,
    *,
    fraction: float = _UNSCOPED_FRACTION,
    min_budget: int = _MIN_UNSCOPED,
    max_budget: int = _MAX_UNSCOPED,
) -> int:
    """A bounded budget for exploration outside the pre-enumerated cells.

    Rigid up-front partitioning into class×surface cells leaves surface
    unexamined, so the orchestrator always reserves at least a minimum of unscoped
    exploration — and scales it with the discovery effort, up to a small cap, so
    it never consumes the whole run. Always at least ``min_budget`` (even with no
    cells enumerated — then unscoped exploration matters most) and never more than
    ``max_budget``.
    """
    scaled = math.ceil(fraction * max(discovery_hunters, 0))
    return max(min_budget, min(max(scaled, min_budget), max_budget))


def is_unscoped_surface(surface_id: str, cells: Iterable[DiscoveryCell]) -> bool:
    """Whether a surface falls outside every pre-enumerated discovery cell.

    A finding on such a surface originated from unscoped exploration; it still
    flows into the same ledger through the same confirmation path as any other.
    """
    return surface_id not in {c.surface_id for c in cells if c.surface_id}


@dataclass(frozen=True)
class DiscoveryAllocation:
    """The auditable discovery allocation root records for a run.

    A deterministic function of the surface inventory — the cell counts, the
    chosen parallel-hunter count, and the unscoped-exploration budget — so the
    orchestration decision is reproducible and recordable on the run's existing
    decision surface (a note), not an opaque constant.
    """

    total_cells: int
    independent_cells: int
    dependent_cells: int
    surface_count: int
    discovery_hunters: int
    unscoped_budget: int

    def as_record(self) -> dict[str, int]:
        """A flat, recordable summary (e.g. the body of an auditable note)."""
        return {
            "total_cells": self.total_cells,
            "independent_cells": self.independent_cells,
            "dependent_cells": self.dependent_cells,
            "surface_count": self.surface_count,
            "discovery_hunters": self.discovery_hunters,
            "unscoped_budget": self.unscoped_budget,
        }


def plan_discovery(
    architecture: Mapping[str, Sequence[Mapping[str, str]]],
    surfaces: Iterable[SurfaceNode],
) -> DiscoveryAllocation:
    """Compute the whole auditable discovery allocation from the live inventory.

    Enumerates the cells, splits independent from dependent (chaining) cells,
    applies the effort-scaling rule to the independent cell count and surface
    inventory, and reserves the unscoped budget — all deterministically, so root
    can record the result and a reader can reproduce it.
    """
    surface_list = list(surfaces)
    cells = discovery_cells(architecture, surface_list)
    independent = independent_cells(cells)
    dependent = dependent_cells(cells)
    hunters = discovery_hunter_allocation(len(independent), len(surface_list))
    budget = unscoped_exploration_budget(hunters)
    return DiscoveryAllocation(
        total_cells=len(cells),
        independent_cells=len(independent),
        dependent_cells=len(dependent),
        surface_count=len(surface_list),
        discovery_hunters=hunters,
        unscoped_budget=budget,
    )


# ── importable descriptions (single source for the generated CONTRACT) ────────

DISCOVERY_FANOUT_DESCRIPTION = (
    "Fan discovery out across independent class×surface cells — each a candidate vulnerability "
    "class (from the architecture-implied-classes enumeration) paired with a typed surface. A "
    "cell is independent only when its surface is reachable without another cell's confirmed "
    "primitive; a cell on a surface reached only through a component depends on a prior primitive "
    "and is routed to the chaining phase, not dispatched as discovery. Each discovery hunter gets "
    "a single-class hunt task scoped to its own cell and writes to the shared ledger, so parallel "
    "hunters on different cells never collide."
)
"""One class-agnostic statement of the parallel-discovery fan-out, read by the generated root
CONTRACT."""

EFFORT_SCALING_DESCRIPTION = (
    "Scale the number of parallel discovery hunters to the surface size — the count of surfaces "
    "and of independent class×surface cells — by the explicit, bounded rule, not a fixed "
    "constant: more cells and a larger surface inventory earn more hunters, up to a hard ceiling "
    "that prevents sprawl, with a floor that prevents under-staffing a large surface. Record the "
    "chosen allocation so the decision is auditable."
)
"""One class-agnostic statement of the effort-scaling rule, read by the generated root CONTRACT."""

UNSCOPED_EXPLORATION_DESCRIPTION = (
    "Reserve a bounded budget for unscoped exploration — investigation not confined to the "
    "pre-enumerated class×surface cells — because a rigid up-front partition leaves surface "
    "unexamined. The budget is explicit and bounded so it never consumes the whole run; findings "
    "from unscoped exploration flow into the same ledger through the same confirmation path as "
    "every other finding."
)
"""One class-agnostic statement of the unscoped-exploration budget, read by the generated root
CONTRACT."""
