"""Regression: the Phase-1 deadlock between the finish-time closure gate and the
``extra="forbid"`` Hypothesis schema (inline hypothesis disposition).

A live run surfaced a deadlock. The closure gate demanded a *disposition* for
every ``open``/``blocked`` hypothesis before ``finish_scan`` would complete; the
agent recorded it the lowest-friction way the logs show it reaching for — an
inline ``disposition:`` field on the hypothesis line — and the ``extra="forbid"``
:class:`Hypothesis` schema rejected the save with
``disposition: Extra inputs are not permitted``. The gate demanded exactly what
the schema forbade recording, so every run paid finish-friction and one in six
logged the hard rejection.

These tests pin the fix end to end: the inline disposition is a first-class,
validated field; a model whose open/blocked hypotheses carry it SAVES; the
closure gate treats those as disposed and lets the scan FINISH; a model with one
open hypothesis left with NO disposition still BLOCKS finish and names it; and the
basis gate and the other hypothesis validations are not weakened. Everything here
is class-agnostic — no specific vulnerability stands in as the subject.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import zen.tools.detected_stack.tools as stack_mod
import zen.tools.threat_model.tools as tm
from zen.tools.finish.tool import _do_finish, _undisposed_open_hypotheses
from zen.tools.threat_model.schema import HYPOTHESIS_DISPOSITION_VALUES
from zen.tools.threat_model.tools import _save_impl


if TYPE_CHECKING:
    from collections.abc import Iterator


_TARGET = "https://app.example.com"
_SCAN = [_TARGET]


@pytest.fixture(autouse=True)
def _isolate_stores() -> Iterator[None]:
    """Each test is its own run: clear the threat-model and architecture stores.

    The closure gate reads the threat-model store, and the save's discovery and
    completeness gates read the architecture store; both must start empty (so the
    architecture-driven gates are no-ops here) and must not leak into another
    test's finish path.
    """
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


# A complete, gate-passing model: all six required sections, well-formed
# hypotheses, and no architecture registered (so the discovery and completeness
# gates are no-ops). Only the Hypotheses body varies per test.
_HEAD = """# Threat Model

## Overview
A standalone service used directly by its clients. Product code only; no separate
tooling is deployed here.

## Architecture
A single application component handles requests directly from its clients; no
intermediary stages sit in front of it.

## Trust Boundaries and Assumptions
Requests arrive from untrusted clients. The component enforces its own access
control; nothing upstream pre-authenticates on its behalf.

## Observations
The public request surface is attacker-reachable. One application component was
observed; no backend services sit behind it.

## Hypotheses
"""

_TAIL = """
## Severity Calibration
Critical: full takeover. High: cross-user read. Medium: self-scoped leak. Low:
verbose errors.
"""

# Two leads left open/blocked, each carrying an INLINE disposition — exactly the
# shape the live agent wrote and the schema used to reject with
# "disposition: Extra inputs are not permitted".
_DISPOSED = (
    "- id: H1 | basis: assumed | mechanism: a crafted request abuses application logic | "
    "predicted_observable: an action completes that policy should forbid | state: open | "
    "disposition: deferred | disposition_reason: needs an authenticated session we could not "
    "obtain in the engagement window\n"
    "- id: H2 | basis: assumed | mechanism: a second lead not yet prosecuted | "
    "predicted_observable: a telling response | state: blocked | disposition: accepted_risk | "
    "disposition_reason: acknowledged; not prosecuted this engagement\n"
)

# The same shape, but H2 is left open with NO disposition at all.
_UNDISPOSED = (
    "- id: H1 | basis: assumed | mechanism: a crafted request abuses application logic | "
    "predicted_observable: an action completes that policy should forbid | state: open | "
    "disposition: deferred | disposition_reason: carried forward, needs access we lack\n"
    "- id: H2 | basis: assumed | mechanism: a second lead left unhandled | "
    "predicted_observable: a telling response | state: open\n"
)


def _model(hypotheses: str) -> str:
    return _HEAD + hypotheses + _TAIL


def _finish() -> dict:
    # Report state is unavailable in the unit environment, so a pass returns a
    # not-persisted success; the point here is only whether the closure gate blocked.
    return _do_finish(
        parent_id=None,
        executive_summary="x",
        methodology="x",
        technical_analysis="x",
        recommendations="x",
        agent_graph={},
    )


# --- the deadlock is gone: the inline disposition now SAVES ----------------------


def test_inline_disposition_on_open_and_blocked_hypotheses_now_saves() -> None:
    # Previously rejected at save with "disposition: Extra inputs are not permitted".
    result = _save_impl(_TARGET, _model(_DISPOSED), "root", _SCAN)
    assert result["success"] is True, result


def test_a_disposed_model_lets_the_scan_finish() -> None:
    assert _save_impl(_TARGET, _model(_DISPOSED), "root", _SCAN)["success"] is True

    result = _finish()

    assert result["success"] is True
    assert "Closure gate" not in result.get("error", "")


# --- the gate is NOT weakened: an undisposed open lead still blocks ---------------


def test_an_open_hypothesis_with_no_disposition_still_blocks_finish_and_is_named() -> None:
    # The save itself does not require a disposition (that is the finish gate's
    # job), so a model with an undisposed lead still saves...
    assert _save_impl(_TARGET, _model(_UNDISPOSED), "root", _SCAN)["success"] is True

    # ...but finish refuses while H2 is open with no disposition, naming it.
    result = _finish()

    assert result["success"] is False
    assert result["scan_completed"] is False
    assert "H2" in result["error"]
    assert result["undisposed_hypotheses"] == ["H2"]


def test_closure_gate_reads_the_inline_disposition_directly() -> None:
    # Unit-level: the disposed leads are not returned as undisposed...
    assert _undisposed_open_hypotheses(_model(_DISPOSED)) == []
    # ...and the one left open with no disposition is.
    assert _undisposed_open_hypotheses(_model(_UNDISPOSED)) == ["H2"]


@pytest.mark.parametrize("disposition", list(HYPOTHESIS_DISPOSITION_VALUES))
def test_every_disposition_value_disposes_a_lead(disposition: str) -> None:
    one = (
        "- id: H1 | basis: assumed | mechanism: x | predicted_observable: y | "
        f"state: blocked | disposition: {disposition}\n"
    )
    assert _undisposed_open_hypotheses(_model(one)) == []


# --- basis gate and the other validations are intact -----------------------------


def test_a_disposition_does_not_excuse_a_missing_basis_conditional_field() -> None:
    # basis: observed still requires supporting_evidence_ids, disposition or not.
    bad = (
        "- id: H1 | basis: observed | mechanism: x | predicted_observable: y | "
        "state: open | disposition: deferred\n"
    )
    result = _save_impl(_TARGET, _model(bad), "root", _SCAN)
    assert result["success"] is False
    assert "H1" in result["error"]
    assert "supporting_evidence_id" in result["error"]


def test_an_unknown_disposition_value_is_rejected_field_level() -> None:
    bad = (
        "- id: H1 | basis: assumed | mechanism: x | predicted_observable: y | "
        "state: open | disposition: maybe_later\n"
    )
    result = _save_impl(_TARGET, _model(bad), "root", _SCAN)
    assert result["success"] is False
    # Field-level and actionable: names the field and lists a valid value.
    assert "disposition" in result["error"]
    assert "deferred" in result["error"]
