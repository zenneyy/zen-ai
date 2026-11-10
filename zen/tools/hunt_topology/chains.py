"""The chaining agent's two structural gates (Phase 2, item 2.3).

A chain composes confirmed primitives toward an impact objective. Two failures
the matched-pair evaluation surfaced are fixed here, as pure, importable checks
over a :class:`~zen.tools.ledger.objects.ChainPlan`:

**1. The per-hop distinct-class decomposition gate (the F5 fix).**
The evaluation established that chain *depth* is not the bottleneck — a chain
composed reliably to full depth. The real signal was in *decomposition*: when the
composition plumbing resembles one vulnerability class, a plan can model the whole
chain through that single framing and under-model a required *terminal* hop of a
different class, so that hop is never tasked. :func:`decomposition_problems`
refuses exactly that: every hop on the planned path — *including the terminal hop
that reaches the objective* — must carry its own enumerated candidate primitive
and the class it belongs to, and the terminal hop must be its own distinct entry.
The gate is **generic**: it checks that every hop names *a* candidate primitive
and *a* class and that the terminal hop is distinct — never that any *specific*
class appears, and never a particular class sequence. This is the owner/field/
gate/probe discipline of item 1.5 applied to chain hops.

This gate is a sound structural forcing function on its own merits. It is **not**
claimed to be validated against a measured heterogeneity bottleneck: the
heterogeneity signal that motivated attention to decomposition is confounded on
the only target that produced it and cannot be cleanly measured until a
parity-controlled target exists, so this is deliberately plain structure, not a
heuristic tuned to that effect. The refuted "unintended-shortcut" framing is not
reintroduced here — the gate forces a distinct primitive per hop, it does not try
to stop a surface being reached by an unintended route.

**2. The confirmed-primitive advancement check (the reach≠perform fix).**
"Reached the surface" is not "performed the exploit." Advancing the chain past a
hop requires that hop's intended primitive to be *confirmed* — a
:class:`~zen.tools.ledger.objects.Finding` the ledger holds in ``confirmed``,
reachable only through a passing :class:`~zen.tools.ledger.objects.ValidatorVerdict`
(the section-2.2 socket). :func:`hop_confirmed` reads that state back from the
finding itself; it consults **no** reach/trace signal, so re-reaching a deeper
surface can never satisfy a hop whose primitive is unconfirmed. There is exactly
one notion of "confirmed" in the engine, and this is it. A hop that cannot be
driven to a confirmed primitive is recorded UNACHIEVED (a disposition on the hop),
never silently dropped.

Everything here is class-agnostic.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol


if TYPE_CHECKING:
    from zen.tools.ledger.objects import ChainHop, ChainPlan, Finding


__all__ = [
    "CONFIRMED_ADVANCEMENT_DESCRIPTION",
    "DECOMPOSITION_GATE_DESCRIPTION",
    "SINGLE_CONTEXT_DESCRIPTION",
    "ChainDecompositionError",
    "FindingSource",
    "assert_decomposition_complete",
    "blocking_hops",
    "chain_claimable",
    "chain_reaches_objective",
    "claimable_depth",
    "decomposition_complete",
    "decomposition_problems",
    "hop_confirmed",
    "unconfirmed_hops",
]


class ChainDecompositionError(ValueError):
    """A chain plan failed the per-hop distinct-class decomposition gate.

    Raised by :func:`assert_decomposition_complete` (and the ledger's
    ``record_chain``). The message names the exact hop and field to fix, so a
    caller corrects the decomposition rather than routing around the gate.
    """


class FindingSource(Protocol):
    """The slice of the ledger the advancement check needs: look a finding up.

    Depending only on this shape keeps the advancement logic a pure function of
    recorded findings — testable with a stub and free of any import cycle with
    the ledger store.
    """

    def get_finding(self, finding_id: str) -> Finding | None:
        """Return the recorded finding with ``finding_id``, or ``None``."""
        ...


def _norm(text: str) -> str:
    """Normalize a primitive description for the distinctness comparison."""
    return " ".join(text.split()).lower()


# ── the per-hop distinct-class decomposition gate (the F5 fix) ────────────────


def decomposition_problems(plan: ChainPlan) -> list[str]:
    """Problems that make ``plan``'s decomposition incomplete, newest-first empty.

    An empty list means the plan is fully decomposed: every hop (including the
    terminal hop) enumerates its own candidate primitive and a class, exactly one
    hop reaches the objective, and no hop reuses another's primitive. A non-empty
    list names each problem by the hop and field to fix. Generic throughout — it
    reasons about the *presence* and *distinctness* of each hop's enumerated
    fields, never about which class a hop names.
    """
    if not plan.hops:
        return [
            "the chain plan enumerates no hops: a chain traverses at least one surface, and "
            "each hop — including the terminal hop that reaches the impact objective — must be "
            "enumerated with its own candidate primitive and class."
        ]

    problems: list[str] = []

    # Field presence per hop — every hop names a candidate primitive and a class.
    for hop in sorted(plan.hops, key=lambda h: h.index):
        label = f"hop {hop.index}"
        if hop.target_surface:
            label += f" (surface {hop.target_surface})"
        if not hop.candidate_primitive.strip():
            problems.append(
                f"{label} has no candidate_primitive: every hop on the planned path must "
                "enumerate its own distinct candidate primitive, so a terminal hop of a "
                "different class cannot be swallowed by an earlier hop's framing."
            )
        if not hop.candidate_class.strip():
            problems.append(
                f"{label} has no candidate_class: every hop's candidate primitive must name "
                "the vulnerability class it belongs to (the class is read as data; the gate "
                "requires that one is named, not which one)."
            )

    # The terminal hop is enumerated, and exactly one — the under-modeled-terminal
    # failure is a plan that reaches for the objective with no terminal hop.
    terminals = [h for h in plan.hops if h.terminal]
    if not terminals:
        problems.append(
            "no hop is flagged terminal: the hop that reaches the impact objective "
            f"'{plan.impact_objective}' must be enumerated as its own hop with its own distinct "
            "candidate primitive and class — a plan that stops at the enabling primitive "
            "under-models the terminal hop and it is never tasked."
        )
    elif len(terminals) > 1:
        idents = ", ".join(str(h.index) for h in sorted(terminals, key=lambda h: h.index))
        problems.append(
            f"more than one hop is flagged terminal ({idents}): exactly one terminal hop reaches "
            "the impact objective."
        )

    # Distinctness — each hop a distinct candidate primitive. A terminal hop that
    # echoes an earlier hop's primitive is the "collapse into one framing" signature.
    seen: dict[str, int] = {}
    for hop in sorted(plan.hops, key=lambda h: h.index):
        key = _norm(hop.candidate_primitive)
        if not key:
            continue  # already reported as missing above
        if key in seen:
            problems.append(
                f"hop {hop.index} reuses the candidate primitive of hop {seen[key]}: each hop — "
                "above all the terminal hop — must enumerate a DISTINCT candidate primitive, or "
                "the chain is modeled through a single framing that swallows a hop of a "
                "different class."
            )
        else:
            seen[key] = hop.index

    return problems


def decomposition_complete(plan: ChainPlan) -> bool:
    """Whether ``plan`` passes the per-hop distinct-class decomposition gate."""
    return not decomposition_problems(plan)


def assert_decomposition_complete(plan: ChainPlan) -> None:
    """Raise :class:`ChainDecompositionError` if ``plan`` is not fully decomposed.

    The field-level enforcement point the ledger's ``record_chain`` and the
    ``record_chain_plan`` tool call before a chain is accepted — so a collapsed or
    terminal-omitting plan is refused *before composition*, naming the hop to fix.
    """
    problems = decomposition_problems(plan)
    if problems:
        joined = "; ".join(problems)
        msg = (
            f"chain plan {plan.id!r} is not fully decomposed — every hop (including the "
            "terminal hop) must enumerate a distinct candidate primitive and the class it "
            f"belongs to: {joined}"
        )
        raise ChainDecompositionError(msg)


# ── the confirmed-primitive advancement check (the reach≠perform fix) ─────────


def hop_confirmed(hop: ChainHop, source: FindingSource) -> bool:
    """Whether ``hop``'s intended primitive is confirmed — the section-2.2 socket.

    True only when the hop names a ``finding_id`` the ledger holds in
    ``confirmed`` (a state reachable only through a passing validator verdict).
    This consults the finding's own state and **nothing** about whether a surface
    was reached, so re-reaching a deeper surface never satisfies a hop whose
    intended primitive is unconfirmed.
    """
    finding_id = hop.finding_id.strip()
    if not finding_id:
        return False
    finding = source.get_finding(finding_id)
    return finding is not None and finding.state == "confirmed"


def claimable_depth(plan: ChainPlan, source: FindingSource) -> int:
    """How far the chain may be claimed: the count of leading confirmed hops.

    The chain can be claimed only as far as its hops are confirmed *in order*; the
    first unconfirmed hop blocks claiming anything past it, however deep a later
    surface was reached.
    """
    depth = 0
    for hop in sorted(plan.hops, key=lambda h: h.index):
        if not hop_confirmed(hop, source):
            break
        depth += 1
    return depth


def unconfirmed_hops(plan: ChainPlan, source: FindingSource) -> list[ChainHop]:
    """The hops whose intended primitive is not confirmed, in order."""
    return [h for h in sorted(plan.hops, key=lambda h: h.index) if not hop_confirmed(h, source)]


def blocking_hops(plan: ChainPlan, source: FindingSource) -> list[ChainHop]:
    """Unconfirmed hops that are *also* not dispositioned UNACHIEVED.

    These are the hops that block the chain being claimed and would block closure:
    an unconfirmed hop with no ``unachieved_disposition`` is an open lead. A hop
    recorded UNACHIEVED is handled (a disposition), so it does not appear here even
    though it is unconfirmed — it simply caps how far the chain can be claimed.
    """
    return [h for h in unconfirmed_hops(plan, source) if h.unachieved_disposition is None]


def chain_claimable(plan: ChainPlan, source: FindingSource) -> bool:
    """Whether every hop (including the terminal hop) is confirmed.

    The chain may be claimed to its impact objective only when all its hops are
    confirmed — a single unconfirmed hop anywhere on the path means the end-to-end
    impact has not been demonstrated.
    """
    return bool(plan.hops) and all(hop_confirmed(h, source) for h in plan.hops)


def chain_reaches_objective(plan: ChainPlan, source: FindingSource) -> bool:
    """Whether the composed chain actually reaches its impact objective.

    Ties the two gates together: the objective is reached only when the plan is
    fully decomposed (every hop, including the terminal, is its own distinct
    candidate primitive and class) **and** every hop is confirmed. This is why a
    multi-step objective succeeds through composition where independent single-step
    work does not: a single enabling primitive is neither decomposed to the
    terminal hop nor, alone, the confirmed terminal — so it does not reach the
    composed objective, while a decomposed, fully-confirmed chain does.
    """
    return decomposition_complete(plan) and chain_claimable(plan, source)


# ── importable descriptions (single source for the generated CONTRACT) ────────

DECOMPOSITION_GATE_DESCRIPTION = (
    "Before composing, decompose the chain into its true per-hop structure: for every hop "
    "required to reach the impact objective — including the terminal hop — enumerate a distinct "
    "candidate primitive and the vulnerability class it belongs to. A plan that collapses "
    "distinct-class hops into one framing, or omits the terminal hop's own distinct candidate "
    "primitive, is an incomplete decomposition and is rejected before composition. The gate is "
    "generic: it checks that every hop names a candidate primitive and a class and that the "
    "terminal hop is its own distinct entry — never that any particular class appears."
)
"""One class-agnostic statement of the per-hop distinct-class decomposition gate, read by the
generated chaining CONTRACT so the text that teaches and the gate that enforces share one source."""

CONFIRMED_ADVANCEMENT_DESCRIPTION = (
    "Advancing the chain past a hop requires that hop's intended primitive to be CONFIRMED — a "
    "finding carried to 'confirmed' through a passing validator verdict (the same confirmed "
    "notion the validator socket enforces), not merely that a deeper surface was reached. "
    "Re-reaching a surface is never hop-completion. A hop whose intended primitive is unconfirmed "
    "blocks claiming the chain past it: either drive that primitive to a confirmed verdict via "
    "the hunter/validator path, or record the hop UNACHIEVED with a disposition — never drop it "
    "silently."
)
"""One class-agnostic statement of the confirmed-primitive advancement rule, read by the generated
chaining CONTRACT."""

SINGLE_CONTEXT_DESCRIPTION = (
    "You run as one long-lived context across the whole composition — you are not fragmented into "
    "short-lived per-hop agents, because splitting dependency-heavy composition across agents is "
    "exactly the context-loss anti-pattern that drops a required hop. Hold the full hop vector in "
    "one context; where a specific hop's primitive still needs to be driven to a confirmed "
    "verdict, task a single-class hunter/validator for that hop and fold its confirmed result "
    "back into your plan."
)
"""One class-agnostic statement of the single-long-lived-context discipline, read by the generated
chaining CONTRACT."""
