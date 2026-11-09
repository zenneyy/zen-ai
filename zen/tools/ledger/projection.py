"""Project recon's free-text request path onto typed :class:`SurfaceNode`s.

Recon registers the request path as a list of ``{name, role}`` hops written in
prose. The ledger stores them as typed surfaces so the gates and section 2.2 can
read *structure* (reachability, trust context, the kind of component) instead of
re-parsing the prose. This module is that projection, and it is deliberately
**behavior-preserving**: a surface's ``reachability`` is computed by the same
primary-application walk the indirect-service enumeration gate has always used,
so the object-backed gate flags exactly the services the prose-based one did.

The ``kind`` it assigns is the typed structural label the 2.1 seam called for —
a first, advisory step toward the implied-classes mapping consuming typed kinds
instead of keyword-sniffing free text. It never overrides the raw ``name``/
``role`` (those are kept verbatim on the surface), so nothing downstream that
still reads the raw hop text changes behavior.

Everything here is class-agnostic: it recognises *what a component does to
traffic* and *where it sits in the path*, never a vulnerability class.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from zen.tools.ledger.objects import Reachability, SurfaceNode


if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


__all__ = [
    "is_enumerable_backend",
    "is_infrastructure_hop",
    "surfaces_from_hops",
]


# Mirrors ``zen.tools.threat_model.tools._INFRASTRUCTURE_KEYWORDS``. Duplicated
# here (rather than imported) only to avoid an import cycle — threat_model.tools
# imports the ledger, so the ledger cannot import it back. The two lists must
# stay in step; the behavior-equivalence test on the gate fixtures guards that.
_INFRASTRUCTURE_KEYWORDS: frozenset[str] = frozenset({
    "load balancer",
    "proxy",
    "gateway",
    "cache",
    "waf",
    "firewall",
    "cdn",
    "content delivery",
    "entry point",
    "tls terminat",
    "ssl terminat",
})


def _hop_text(hop: Mapping[str, str]) -> str:
    return f"{hop.get('name', '')} {hop.get('role', '')}".lower()


def is_infrastructure_hop(hop: Mapping[str, str]) -> bool:
    """True for edge/transport infrastructure (proxy, gateway, load balancer).

    Behavior-equivalent to ``threat_model.tools._is_infrastructure_hop``.
    """
    return any(term in _hop_text(hop) for term in _INFRASTRUCTURE_KEYWORDS)


def is_enumerable_backend(hop: Mapping[str, str]) -> bool:
    """True for a distinct backend application with its own route surface.

    Behavior-equivalent to ``threat_model.tools._is_enumerable_backend``:
    infrastructure and the primary web application are excluded.
    """
    combined = _hop_text(hop)
    if any(term in combined for term in _INFRASTRUCTURE_KEYWORDS):
        return False
    return not (
        ("web application" in combined or "application server" in combined)
        and "backend" not in combined
    )


def _kind_of(hop: Mapping[str, str]) -> str:
    """A coarse typed structural kind for the surface (advisory; the 2.1 seam)."""
    if is_infrastructure_hop(hop):
        return "transforming_intermediary"
    if is_enumerable_backend(hop):
        return "application_handler"
    return "primary_application"


def surfaces_from_hops(
    identity: str, hops: Sequence[Mapping[str, str]]
) -> list[SurfaceNode]:
    """Project an ordered hop list onto typed surfaces for one target.

    ``reachability`` is set by the primary-application walk the enumeration gate
    uses: the leading infrastructure run and the first non-infrastructure hop
    (the primary application, whose routes edge-targeted discovery already
    covers) are ``publicly_reachable``; everything behind the primary application
    is ``reached_through_component`` — reachable only indirectly. The gate reads
    that field to pick candidate indirect services.
    """
    hop_dicts = [dict(h) for h in hops]
    primary_index = next(
        (i for i, hop in enumerate(hop_dicts) if not is_infrastructure_hop(hop)),
        None,
    )
    nodes: list[SurfaceNode] = []
    for index, hop in enumerate(hop_dicts):
        name = str(hop.get("name", "")).strip()
        role = str(hop.get("role", "")).strip()
        reachability: Reachability = "publicly_reachable"
        trust_context = "edge-facing" if is_infrastructure_hop(hop) else "primary application"
        if primary_index is not None and index > primary_index:
            reachability = "reached_through_component"
            trust_context = "reached only through an upstream component"
        elif primary_index is None:
            # An all-infrastructure path has no application behind it; nothing is
            # an indirect service, so leave every hop publicly reachable.
            reachability = "publicly_reachable"
        nodes.append(
            SurfaceNode(
                id=f"{identity}#{index}",
                source_identity=identity,
                taxonomy="component_hop",
                name=name,
                role=role,
                kind=_kind_of(hop),
                reachability=reachability,
                trust_context=trust_context,
                order_index=index,
            )
        )
    return nodes
