"""Reasoning-regression probe — deterministic / offline (item 1.5; 1.6 seam).

This probe guards the exact regression item 1.5 exists to prevent: an attack
class implied *only by the system's structure* — reachable by inference, with no
directly observed surface — being silently dropped from the hypothesis set. Each
fixture is a purely structural, class-agnostic architecture whose shape implies a
class for which nothing was observed:

* a component reachable only through another component's server-side behavior
  (an indirect-reach structure); and
* a boundary between two adjacent components that may interpret the same input
  differently (a parser-authority boundary).

The probe feeds each fixture's architecture through
:func:`zen.tools.threat_model.implied_classes.implied_classes` and the
completeness gate (:func:`zen.tools.threat_model.tools.unaddressed_implied_classes`)
and asserts both that the structurally-implied class is produced and that a model
omitting it is flagged, naming it. It is fully deterministic and offline: no live
agent, no seeds, no sampling.

1.6 SEAM — this probe is deliberately shaped so the variance-aware evaluation
harness (item 1.6) can wrap it in a k-seed runner and report pass@k / pass^k over
a live agent's reasoning, rather than over this offline check. Building that
runner, executing the live agent, and deciding grader/target quarantine are 1.6 /
2.10 concerns and are intentionally NOT done here. The fixtures stay in-repo for
now. Nothing below should be changed into a live or sampled check without 1.6.
"""

from __future__ import annotations

import pytest

from zen.tools.threat_model.implied_classes import implied_classes
from zen.tools.threat_model.tools import unaddressed_implied_classes


# A component reachable only through another component's server-side behavior.
# Structure, not technique: the inner component is never directly exposed, so the
# class it implies has no observed surface — it exists only by inference.
_INDIRECT_REACH_ARCH: dict[str, list[dict[str, str]]] = {
    "fixture": [
        {"name": "public-component", "role": "public request handler"},
        {
            "name": "inner-component",
            "role": "component reachable only through the public component's server-side requests",
        },
    ]
}

# A boundary between two adjacent components that may interpret the same input
# differently. The class this implies lives at the boundary, not on any single
# component's observed surface.
_PARSER_BOUNDARY_ARCH: dict[str, list[dict[str, str]]] = {
    "fixture": [
        {"name": "front-tier", "role": "normalizes and forwards requests to the component behind it"},
        {"name": "rear-tier", "role": "interprets the forwarded requests on its own terms"},
    ]
}

# (architecture, a class the structure implies with no observed surface)
_PROBES: tuple[tuple[dict[str, list[dict[str, str]]], str], ...] = (
    (_INDIRECT_REACH_ARCH, "ssrf"),
    (_PARSER_BOUNDARY_ARCH, "semantic_confusion"),
)

# A minimal model whose Hypotheses section names no class at all, so it addresses
# none of the implied classes — the "silently dropped" state the gate must catch.
_MODEL_OMITTING_EVERYTHING = (
    "# Threat Model\n\n## Hypotheses\n"
    "- id: H1 | basis: assumed | mechanism: x | predicted_observable: y\n"
)


@pytest.mark.parametrize(("architecture", "implied_class"), _PROBES)
def test_structural_class_is_produced(
    architecture: dict[str, list[dict[str, str]]], implied_class: str
) -> None:
    """The class the structure implies is enumerated from the architecture alone."""
    assert implied_class in implied_classes(architecture)


@pytest.mark.parametrize(("architecture", "implied_class"), _PROBES)
def test_a_model_omitting_the_structural_class_is_flagged(
    architecture: dict[str, list[dict[str, str]]], implied_class: str
) -> None:
    """A model that neither hypothesizes nor dismisses the implied class is caught,
    and once it is addressed the completeness gate clears it."""
    unaddressed = {c for c, _ in unaddressed_implied_classes(_MODEL_OMITTING_EVERYTHING, architecture)}
    assert implied_class in unaddressed

    dismissed = _MODEL_OMITTING_EVERYTHING + (
        "\n## Dismissed Implied Classes\n"
        f"- vuln_class: {implied_class} | reason: recorded here as a deliberate, reasoned decision\n"
    )
    cleared = {c for c, _ in unaddressed_implied_classes(dismissed, architecture)}
    assert implied_class not in cleared
