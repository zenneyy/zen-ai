"""Hunting topology (Phase 2, item 2.3): discovery fan-out, chaining, bypassing.

This package carries the *structural* half of section 2.3 — the forcing functions
and enumerations the orchestration personas drive, kept as pure, importable logic
so a gate and the prompt that teaches it read one source and cannot drift:

* :mod:`~zen.tools.hunt_topology.chains` — the chaining agent's two gates. The
  **per-hop distinct-class decomposition** gate (the review's chain-decomposition
  forcing function) refuses a chain plan that collapses distinct-class hops into a
  single framing or under-models the terminal hop; the **confirmed-primitive
  advancement** check reads a hop's satisfaction back from its finding's own
  ``confirmed`` state (the section-2.2 socket), so surface-reach is never
  mistaken for hop-completion.
* :mod:`~zen.tools.hunt_topology.discovery` — the parallel-discovery fan-out:
  independent class×surface cells drawn from the 1.5 architecture-implied-classes
  enumeration and the ledger's typed surfaces, the effort-scaling allocation, and
  the unscoped-exploration budget.
* :mod:`~zen.tools.hunt_topology.tools` — ``record_chain_plan``, the agent-facing
  entry point that runs the decomposition gate before composition and records the
  chain to the research ledger.

Everything here is **class-agnostic**: it reasons about surfaces, hops, candidate
primitives, and cells in general terms, and privileges no vulnerability class,
technique, scenario, or target shape. Catalog class slugs that appear are data,
never behavior.
"""

from __future__ import annotations

from zen.tools.hunt_topology.chains import (
    CONFIRMED_ADVANCEMENT_DESCRIPTION,
    DECOMPOSITION_GATE_DESCRIPTION,
    SINGLE_CONTEXT_DESCRIPTION,
    ChainDecompositionError,
    assert_decomposition_complete,
    blocking_hops,
    chain_claimable,
    chain_reaches_objective,
    claimable_depth,
    decomposition_complete,
    decomposition_problems,
    hop_confirmed,
    unconfirmed_hops,
)
from zen.tools.hunt_topology.discovery import (
    DISCOVERY_FANOUT_DESCRIPTION,
    EFFORT_SCALING_DESCRIPTION,
    UNSCOPED_EXPLORATION_DESCRIPTION,
    DiscoveryAllocation,
    DiscoveryCell,
    dependent_cells,
    discovery_cells,
    discovery_hunter_allocation,
    independent_cells,
    is_unscoped_surface,
    plan_discovery,
    unscoped_exploration_budget,
)


__all__ = [
    "CONFIRMED_ADVANCEMENT_DESCRIPTION",
    "DECOMPOSITION_GATE_DESCRIPTION",
    "DISCOVERY_FANOUT_DESCRIPTION",
    "EFFORT_SCALING_DESCRIPTION",
    "SINGLE_CONTEXT_DESCRIPTION",
    "UNSCOPED_EXPLORATION_DESCRIPTION",
    "ChainDecompositionError",
    "DiscoveryAllocation",
    "DiscoveryCell",
    "assert_decomposition_complete",
    "blocking_hops",
    "chain_claimable",
    "chain_reaches_objective",
    "claimable_depth",
    "decomposition_complete",
    "decomposition_problems",
    "dependent_cells",
    "discovery_cells",
    "discovery_hunter_allocation",
    "hop_confirmed",
    "independent_cells",
    "is_unscoped_surface",
    "plan_discovery",
    "unconfirmed_hops",
    "unscoped_exploration_budget",
]
