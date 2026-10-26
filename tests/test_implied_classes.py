"""Architecture-implied-classes forcing function + closure gate (item 1.5).

These pin the three structural guarantees 1.5 adds, all class-agnostic:

* :func:`implied_classes` maps the documented *structure* (component roles and
  the boundaries between adjacent components) to candidate vulnerability-class
  families, drawing names only from the shipped catalog, and no-ops on empty
  state;
* the save-time **completeness gate** refuses a threat model that leaves any
  architecture-implied class neither hypothesized nor explicitly dismissed,
  naming the class and the component or boundary that implied it, and is a no-op
  when no architecture is registered;
* the finish-time **closure gate** refuses to end a run while any hypothesis is
  left open or blocked with no recorded disposition (a terminal state or an
  explicit deferral).

No specific technique, benchmark, or scenario stands in as the subject — the
fixtures are neutral structural placeholders.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import zen.tools.detected_stack.tools as stack_mod
import zen.tools.threat_model.tools as tm
from zen.skills import get_vulnerability_class_names
from zen.tools.finish.tool import _do_finish, _undisposed_open_hypotheses
from zen.tools.threat_model.implied_classes import implied_classes
from zen.tools.threat_model.tools import _save_impl, unaddressed_implied_classes


if TYPE_CHECKING:
    from collections.abc import Iterator


_TARGET = "https://app.example.com"
_SCAN = [_TARGET]


@pytest.fixture(autouse=True)
def _isolate_stores() -> Iterator[None]:
    """Clear the threat-model and architecture stores around each test."""
    orig_models = dict(tm._MODELS)
    orig_model_path = tm._store_path
    orig_arch = dict(stack_mod._DETECTED_ARCHITECTURE)
    orig_arch_path = stack_mod._arch_store_path
    tm._MODELS.clear()
    tm._store_path = None
    stack_mod._DETECTED_ARCHITECTURE.clear()
    stack_mod._arch_store_path = None
    try:
        yield
    finally:
        tm._MODELS.clear()
        tm._MODELS.update(orig_models)
        tm._store_path = orig_model_path
        stack_mod._DETECTED_ARCHITECTURE.clear()
        stack_mod._DETECTED_ARCHITECTURE.update(orig_arch)
        stack_mod._arch_store_path = orig_arch_path


def _register(hops: list[dict[str, str]]) -> None:
    stack_mod._DETECTED_ARCHITECTURE[_TARGET] = hops


# A valid single-application-component model: passes every earlier save gate
# (sections, basis, discovery). Its lone hypothesis names no class, so on its own
# it addresses none of the classes a registered architecture would imply.
_MODEL = """# Threat Model

## Overview
A standalone service. Product code only; no separate tooling is deployed.

## Architecture
A single application component handles requests directly from its clients.

## Trust Boundaries and Assumptions
Requests arrive from untrusted clients. The component enforces its own access
control; nothing upstream pre-authenticates on its behalf.

## Observations
The public request surface is attacker-reachable. One application component was
observed; no backend services sit behind it.

## Hypotheses
- id: H1 | basis: assumed | mechanism: a crafted request abuses application logic | predicted_observable: an action completes that policy should forbid | target_depth: discover | impact_objective: primitive | rationale: standard first-pass suspicion

## Severity Calibration
Critical: full takeover. High: cross-user read. Medium: self-scoped leak. Low:
verbose errors.
"""

# A single non-infrastructure request handler: implies the baseline every
# request-handling surface admits, and nothing narrower.
_APP_HOP = [{"name": "web-app", "role": "application handler"}]
_BASELINE = {"business_logic", "information_disclosure", "broken_function_level_authorization"}


# --- implied_classes: structure → class families ---------------------------------


def test_implied_classes_maps_structure_to_a_family_with_reasons() -> None:
    # A component that fronts durable state implies the stored-data injection and
    # access families, each tagged with the component that implied it.
    implied = implied_classes({_TARGET: [{"name": "primary-datastore", "role": "durable state store"}]})
    assert "sql_injection" in implied
    assert "idor" in implied
    assert implied["sql_injection"].source == "primary-datastore"
    assert "fronts durable state" in implied["sql_injection"].text


def test_implied_classes_marks_a_boundary_implied_class_with_the_boundary() -> None:
    # Two adjacent components where the upstream transforms traffic imply the
    # differential-interpretation family at the *boundary*, named as such.
    implied = implied_classes({
        _TARGET: [
            {"name": "front", "role": "reverse proxy that normalizes requests"},
            {"name": "back", "role": "application handler"},
        ]
    })
    assert "http_request_smuggling" in implied
    assert "front <-> back" in implied["http_request_smuggling"].source


def test_implied_classes_draws_only_catalog_names() -> None:
    catalog = get_vulnerability_class_names()
    implied = implied_classes({
        _TARGET: [
            {"name": "edge", "role": "reverse proxy"},
            {"name": "app", "role": "application server"},
            {"name": "store", "role": "sql database"},
        ]
    })
    assert implied, "a rich architecture should imply something"
    assert set(implied) <= catalog


def test_implied_classes_is_empty_for_empty_or_trivial_architecture() -> None:
    assert implied_classes({}) == {}
    assert implied_classes({_TARGET: []}) == {}


# --- completeness gate: the save-time forcing function ---------------------------


def test_save_rejects_a_model_omitting_an_implied_class_naming_class_and_component() -> None:
    _register(_APP_HOP)

    result = _save_impl(_TARGET, _MODEL, "recon", _SCAN)

    assert result["success"] is False
    # Names at least one unaddressed implied class AND the component that implied it.
    assert any(cls in result["error"] for cls in _BASELINE)
    assert "web-app" in result["error"]


def test_a_hypothesis_naming_the_class_satisfies_the_gate() -> None:
    _register(_APP_HOP)
    # H1 now names one baseline class; the other two are dismissed with reasons.
    model = _MODEL.replace(
        "- id: H1 | basis: assumed |",
        "- id: H1 | basis: assumed | vuln_class: business_logic |",
    ) + (
        "\n## Dismissed Implied Classes\n"
        "- vuln_class: information_disclosure | reason: responses carry no human-facing content\n"
        "- vuln_class: broken_function_level_authorization | reason: a single unprivileged role exists\n"
    )

    assert _save_impl(_TARGET, model, "recon", _SCAN)["success"] is True


def test_a_reasoned_dismissal_satisfies_the_gate() -> None:
    _register(_APP_HOP)
    model = _MODEL + (
        "\n## Dismissed Implied Classes\n"
        + "".join(
            f"- vuln_class: {cls} | reason: ruled out by the single-component structure here\n"
            for cls in sorted(_BASELINE)
        )
    )

    assert _save_impl(_TARGET, model, "recon", _SCAN)["success"] is True


def test_no_architecture_registered_is_a_noop_pass() -> None:
    # Nothing registered → nothing implied → the gate must not fire (no false positive).
    assert stack_mod._DETECTED_ARCHITECTURE == {}
    assert _save_impl(_TARGET, _MODEL, "recon", _SCAN)["success"] is True


def test_unaddressed_shrinks_as_classes_are_addressed() -> None:
    arch = {_TARGET: _APP_HOP}
    # Nothing addressed: the full baseline is unaddressed.
    assert {c for c, _ in unaddressed_implied_classes(_MODEL, arch)} == _BASELINE
    # Dismiss one: it drops out, the rest remain.
    dismissed = _MODEL + (
        "\n## Dismissed Implied Classes\n"
        "- vuln_class: business_logic | reason: no state-changing actions are exposed\n"
    )
    assert {c for c, _ in unaddressed_implied_classes(dismissed, arch)} == _BASELINE - {"business_logic"}


# --- closure gate: no open/blocked hypothesis left undisposed --------------------


def _model_with_hypothesis(state: str, *, deferral: bool = False) -> str:
    body = (
        "# Threat Model\n\n## Hypotheses\n"
        f"- id: H1 | basis: assumed | mechanism: x | predicted_observable: y | state: {state}\n"
    )
    if deferral:
        body += (
            "\n## Deferred Hypotheses\n"
            "- hypothesis_id: H1 | reason: carried forward, needs access we do not have\n"
        )
    return body


@pytest.mark.parametrize("state", ["open", "blocked"])
def test_open_and_blocked_without_disposition_are_undisposed(state: str) -> None:
    assert _undisposed_open_hypotheses(_model_with_hypothesis(state)) == ["H1"]


@pytest.mark.parametrize("state", ["testing", "confirmed", "refuted"])
def test_terminal_or_in_progress_states_are_not_undisposed(state: str) -> None:
    assert _undisposed_open_hypotheses(_model_with_hypothesis(state)) == []


def test_a_deferral_disposes_an_open_hypothesis() -> None:
    assert _undisposed_open_hypotheses(_model_with_hypothesis("open", deferral=True)) == []


def _finish() -> dict:
    return _do_finish(
        parent_id=None,
        executive_summary="x",
        methodology="x",
        technical_analysis="x",
        recommendations="x",
        agent_graph={},
    )


def test_finish_is_blocked_by_an_undisposed_open_hypothesis_naming_it() -> None:
    tm._MODELS["id"] = {"content": _model_with_hypothesis("open")}

    result = _finish()

    assert result["success"] is False
    assert "H1" in result["error"]
    assert result["undisposed_hypotheses"] == ["H1"]


def test_finish_passes_once_the_lead_is_deferred() -> None:
    tm._MODELS["id"] = {"content": _model_with_hypothesis("open", deferral=True)}

    # report state is unavailable in the unit environment, so persistence returns a
    # not-persisted success — the point here is that the closure gate did not block.
    result = _finish()

    assert result["success"] is True
    assert "Closure gate" not in result.get("error", "")


def test_finish_closure_gate_is_a_noop_with_no_models() -> None:
    assert tm._MODELS == {}
    assert _finish()["success"] is True
