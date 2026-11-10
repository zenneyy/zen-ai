"""``record_chain_plan`` — the chaining agent's decomposition gate + ledger record.

The agent-facing entry point for section 2.3's chaining work. It is the point at
which the two structural disciplines bite in a live scan:

* it runs the **per-hop distinct-class decomposition gate**
  (:func:`zen.tools.hunt_topology.chains.decomposition_problems`) *before* a chain
  is accepted, returning a field-level error that names the hop and field to fix —
  so a plan that collapses distinct-class hops into one framing, or omits the
  terminal hop's own distinct candidate primitive, cannot proceed to composition;
* it records the accepted plan to the research ledger (reusing the 2.1 typed
  :class:`~zen.tools.ledger.objects.ChainPlan`, not a parallel store); and
* it reports the **confirmed-primitive advancement** status read back from the
  ledger — how far the chain is claimable and which hops still block it — so the
  agent drives unconfirmed hops to a verdict (or records them UNACHIEVED) rather
  than claiming a chain past a hop whose primitive was never confirmed.

Class-agnostic: it reasons about hops, candidate primitives, and confirmed
findings in general terms and privileges no vulnerability class.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from agents import RunContextWrapper, function_tool

from zen.tools.hunt_topology.chains import (
    blocking_hops,
    chain_claimable,
    claimable_depth,
    decomposition_problems,
)
from zen.tools.ledger.objects import ChainPlan
from zen.tools.ledger.runtime import get_ledger


logger = logging.getLogger(__name__)


def _author(ctx: RunContextWrapper) -> str:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    agent_id = inner.get("agent_id")
    return str(agent_id) if isinstance(agent_id, str) else ""


def _advancement(ledger: Any, plan: ChainPlan) -> dict[str, Any]:
    """Confirmed-primitive advancement status read back from the ledger findings."""
    if ledger is None:
        return {
            "advancement": "unknown",
            "note": (
                "No research ledger is installed, so per-hop confirmation cannot be resolved. "
                "A hop advances only once its intended primitive is a confirmed finding."
            ),
        }
    depth = claimable_depth(plan, ledger)
    blocking = blocking_hops(plan, ledger)
    return {
        "claimable_depth": depth,
        "total_hops": len(plan.hops),
        "chain_claimable": chain_claimable(plan, ledger),
        "blocking_hops": [
            {
                "index": hop.index,
                "candidate_class": hop.candidate_class,
                "candidate_primitive": hop.candidate_primitive,
                "finding_id": hop.finding_id,
                "terminal": hop.terminal,
            }
            for hop in blocking
        ],
        "note": (
            "Advancing the chain past a hop requires that hop's intended primitive confirmed "
            "(a passing validator verdict) — not that a surface was reached. Drive each blocking "
            "hop to a confirmed verdict via the hunter/validator path, or record it UNACHIEVED "
            "with a disposition; never claim the chain past an unconfirmed hop."
        ),
    }


@function_tool(timeout=30)
async def record_chain_plan(ctx: RunContextWrapper, chain_plan: str) -> str:
    """Record a chain composition, gated on a complete per-hop decomposition.

    **For the chaining agent.** Before you compose confirmed primitives into an
    end-to-end chain, record the plan here. The plan must decompose the chain into
    its true per-hop structure: for every hop required to reach the impact
    objective — **including the terminal hop** — a distinct candidate primitive and
    the vulnerability class it belongs to. This is the gate that stops a chain from
    being modeled through a single resembling framing that silently under-models a
    terminal hop of a different class: a plan that collapses distinct-class hops
    into one framing, or omits the terminal hop's own distinct candidate primitive,
    is rejected with the exact hop and field to fix.

    Recording a plan does **not** claim the chain. Advancing the chain past a hop
    requires that hop's intended primitive to be **confirmed** — a finding carried
    to ``confirmed`` through a passing validator verdict — not merely that a deeper
    surface was reached. The response reports how far the chain is claimable and
    which hops still block it, so you drive each unconfirmed hop to a verdict via
    the hunter/validator path, or record it UNACHIEVED with a disposition, rather
    than claiming impact a hop never earned.

    Args:
        chain_plan: A JSON object serializing the chain plan. Required fields:
            ``id``, ``impact_objective`` (one of ``reach`` / ``trigger`` /
            ``primitive`` / ``weaponized`` / ``chained``), and ``hops`` — an
            ordered list where each hop carries ``index``, ``target_surface`` (a
            surface id), ``candidate_class`` (the class this hop's primitive is),
            ``candidate_primitive`` (what capability this hop establishes), and
            ``terminal`` (true for the one hop that reaches the objective). A hop
            names ``finding_id`` once its primitive is a confirmed finding, or
            ``unachieved_disposition`` when it could not be driven to one.
    """
    try:
        plan = ChainPlan.model_validate_json(chain_plan)
    except ValueError as exc:
        return json.dumps(
            {"success": False, "error": f"invalid chain_plan: {exc}"},
            ensure_ascii=False,
            default=str,
        )

    problems = decomposition_problems(plan)
    if problems:
        logger.debug("record_chain_plan rejected — decomposition: %s", problems)
        joined = "; ".join(problems)
        error = (
            f"hops: chain plan {plan.id!r} is not fully decomposed. Every hop — including the "
            "terminal hop that reaches the impact objective — must enumerate its own distinct "
            f"candidate primitive and the class it belongs to. Fix: {joined}"
        )
        return json.dumps(
            {"success": False, "error": error, "decomposition_problems": problems},
            ensure_ascii=False,
            default=str,
        )

    author = _author(ctx)
    if author and not plan.author:
        plan = plan.model_copy(update={"author": author})

    ledger = get_ledger()
    recorded = False
    if ledger is not None:
        try:
            # Already validated above; record without re-running the gate.
            ledger.record_chain(plan, enforce_decomposition=False, agent_id=author)
        except Exception:  # noqa: BLE001 - the ledger is additive; never fail the record on it
            logger.debug("record_chain_plan ledger emit skipped", exc_info=True)
        else:
            recorded = True

    result: dict[str, Any] = {
        "success": True,
        "chain_id": plan.id,
        "impact_objective": plan.impact_objective,
        "hops": len(plan.hops),
        "recorded": recorded,
        "decomposition": "complete",
    }
    result.update(_advancement(ledger, plan))
    return json.dumps(result, ensure_ascii=False, default=str)
