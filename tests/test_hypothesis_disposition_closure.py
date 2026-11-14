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
from zen.tools.threat_model.schema import (
    DEFERRAL_LINE_EXAMPLE,
    DISPOSITION_LINE_EXAMPLE,
    HYPOTHESIS_DISPOSITION_VALUES,
    HYPOTHESIS_EXAMPLE,
    REFUTATION_CONVENTION,
    REFUTATION_LINE_EXAMPLE,
    parse_hypotheses,
)
from zen.tools.threat_model.tools import _amend_impl, _save_impl


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


# --- A1: `refuted` states its grounds ----------------------------------------------

_BASE = "- id: {id} | basis: assumed | mechanism: m | predicted_observable: o | state: {state}"
_GROUNDED = "refutation_basis: attack_failed | refuting_evidence_ids: 101"
_REASONED = (
    "refutation_basis: control_verified | "
    "refutation: the ownership check runs before the read on every route that reaches it"
)


def _lead(lead_id: str, state: str, extra: str = "") -> str:
    return _BASE.format(id=lead_id, state=state) + (f" | {extra}" if extra else "") + "\n"


def test_a_refuted_lead_without_grounds_is_rejected_at_save_naming_every_one() -> None:
    body = _lead("H1", "refuted") + _lead("H2", "refuted", _GROUNDED) + _lead("H3", "refuted")

    result = _save_impl(_TARGET, _model(body), "root", _SCAN)

    assert result["success"] is False
    assert result["malformed_hypotheses"] == ["H1", "H3"]
    assert "'H1'" in result["error"]
    assert "'H3'" in result["error"]
    assert "'H2'" not in result["error"]
    # The rejection carries the exact grammar, and where a not-prosecuted lead belongs.
    assert REFUTATION_LINE_EXAMPLE in result["error"]
    assert "disposition" in result["error"]
    # A rejected save writes nothing.
    assert tm._MODELS == {}


@pytest.mark.parametrize("grounds", [_GROUNDED, _REASONED], ids=["evidence", "reasoning"])
def test_a_refuted_lead_with_grounds_saves_and_finishes(grounds: str) -> None:
    saved = _save_impl(_TARGET, _model(_lead("H1", "refuted", grounds)), "root", _SCAN)
    assert saved["success"] is True, saved

    assert _finish()["success"] is True


def test_a_lead_that_was_not_prosecuted_is_disposed_not_refuted() -> None:
    honest = _lead("H1", "blocked", "disposition: deferred | disposition_reason: not prosecuted")

    assert _save_impl(_TARGET, _model(honest), "root", _SCAN)["success"] is True
    assert _finish()["success"] is True


def test_one_save_rejection_names_convention_and_refutation_offenders_together() -> None:
    body = (
        "- id: H1 | mechanism: m | predicted_observable: o | state: open\n"
        + _lead("H2", "refuted")
        + "- id: H3 | basis: observed | mechanism: m | predicted_observable: o\n"
    )

    result = _save_impl(_TARGET, _model(body), "root", _SCAN)

    assert result["success"] is False
    assert result["malformed_hypotheses"] == ["H1", "H3", "H2"]
    for lead_id in ("'H1'", "'H2'", "'H3'"):
        assert lead_id in result["error"]


def test_a_single_malformed_hypothesis_keeps_the_message_it_always_had() -> None:
    body = "- id: H1 | mechanism: m | predicted_observable: o | state: open\n"
    _, errors = parse_hypotheses(_model(body))

    result = _save_impl(_TARGET, _model(body), "root", _SCAN)

    assert result["error"] == (
        f"Hypotheses: hypothesis 'H1' is not well-formed — {errors[0].message}. Each hypothesis "
        f"is one Markdown list item following the convention, e.g. `{HYPOTHESIS_EXAMPLE}`. "
        "`basis:` is required on every hypothesis; basis 'observed' requires "
        "supporting_evidence_ids and 'inferred_from_architecture' requires an inference_chain."
    )


def test_a_refutation_basis_outside_the_list_gets_the_whole_grammar_in_one_rejection() -> None:
    body = _lead("H1", "refuted", "refutation_basis: by_design | refutation: intended behaviour")

    result = _save_impl(_TARGET, _model(body), "root", _SCAN)

    assert result["success"] is False
    assert result["malformed_hypotheses"] == ["H1"]
    assert "refutation_basis: Input should be" in result["error"]
    # One rejection carries the valid kinds and where a non-refutation belongs.
    assert REFUTATION_CONVENTION in result["error"]
    assert "accepted_risk" in result["error"]


def test_a_new_save_of_refuted_plus_a_disposition_without_grounds_names_both_fixes() -> None:
    disposed = "disposition: resolved_elsewhere | disposition_reason: covered by H2"

    result = _save_impl(_TARGET, _model(_lead("H1", "refuted", disposed)), "root", _SCAN)

    assert result["success"] is False
    assert result["malformed_hypotheses"] == ["H1"]
    assert "refutation_basis" in result["error"]
    assert "set the state back to open or blocked and keep the disposition" in result["error"]
    assert tm._MODELS == {}
    # Either honest fix saves.
    grounded = _lead("H1", "refuted", f"disposition: resolved_elsewhere | {_REASONED}")
    relabelled = _lead("H1", "blocked", disposed)
    assert _save_impl(_TARGET, _model(grounded), "root", _SCAN)["success"] is True
    assert _save_impl(_TARGET, _model(relabelled), "root", _SCAN)["success"] is True


# --- A2: `testing` is undisposed at the finish boundary, and only there -------------


def test_a_testing_lead_saves_mid_run_but_blocks_finish_and_is_named() -> None:
    # The schema and the save are unchanged: `testing` is valid while the scan runs.
    assert _save_impl(_TARGET, _model(_lead("H1", "testing")), "root", _SCAN)["success"] is True

    result = _finish()

    assert result["success"] is False
    assert result["undisposed_hypotheses"] == ["H1"]
    assert result["undisposed_reasons"] == {"H1": "testing"}
    assert "H1 (testing)" in result["error"]


@pytest.mark.parametrize("channel", ["inline", "deferral-record"])
def test_a_testing_lead_is_disposed_by_either_channel(channel: str) -> None:
    if channel == "inline":
        body, tail = _lead("H1", "testing", "disposition: deferred"), ""
    else:
        body = _lead("H1", "testing")
        tail = "\n## Deferred Hypotheses\n- hypothesis_id: H1 | reason: its hunter was stopped\n"
    assert _save_impl(_TARGET, _HEAD + body + tail + _TAIL, "root", _SCAN)["success"] is True

    assert _finish()["success"] is True


# --- leads that reached the store without passing the save gate ---------------------


def test_a_legacy_refuted_lead_without_grounds_blocks_finish_and_is_named() -> None:
    # A model saved before the rule existed, as a resumed run hydrates it.
    tm._MODELS["legacy"] = {"content": _model(_lead("H1", "refuted"))}

    result = _finish()

    assert result["success"] is False
    assert result["undisposed_reasons"] == {"H1": "refuted without grounds"}
    assert REFUTATION_LINE_EXAMPLE in result["error"]


@pytest.mark.parametrize(
    "fixed",
    [
        _lead("H1", "refuted", _GROUNDED),
        _lead("H1", "refuted", "disposition: resolved_elsewhere"),
        _lead("H1", "blocked", "disposition: deferred"),
    ],
    ids=["grounds-added", "recorded-disposition", "relabelled-as-deferred"],
)
def test_a_legacy_refuted_lead_is_cleared_by_grounds_or_a_disposition(fixed: str) -> None:
    tm._MODELS["legacy"] = {"content": _model(fixed)}

    assert _finish()["success"] is True


def test_the_closure_rejection_names_every_lead_with_the_grammar_to_fix_each() -> None:
    tm._MODELS["m"] = {
        "content": _model(_lead("H1", "open") + _lead("H2", "testing") + _lead("H3", "refuted"))
    }

    result = _finish()

    assert result["undisposed_hypotheses"] == ["H1", "H2", "H3"]
    assert "H1 (open), H2 (testing), H3 (refuted without grounds)" in result["error"]
    for grammar in (DISPOSITION_LINE_EXAMPLE, DEFERRAL_LINE_EXAMPLE, REFUTATION_LINE_EXAMPLE):
        assert grammar in result["error"]
    # Where the fix goes: the saved model, not an amendment.
    assert "save_threat_model" in result["error"]
    assert "amendment" in result["error"]


def test_an_amendment_does_not_dispose_a_lead() -> None:
    assert _save_impl(_TARGET, _model(_lead("H1", "open")), "root", _SCAN)["success"] is True
    amended = _amend_impl(
        _TARGET,
        "## Deferred Hypotheses\n"
        "- hypothesis_id: H1 | reason: carried forward, no access to test it in this engagement",
        "root",
        _SCAN,
    )
    assert amended["success"] is True

    assert _finish()["undisposed_hypotheses"] == ["H1"]


def test_a_rejected_save_leaves_the_stored_model_untouched() -> None:
    good = _model(_lead("H1", "blocked", "disposition: deferred"))
    assert _save_impl(_TARGET, good, "root", _SCAN)["success"] is True
    before = {identity: dict(model) for identity, model in tm._MODELS.items()}

    rejected = _save_impl(_TARGET, _model(_lead("H1", "refuted")), "root", _SCAN)

    assert rejected["success"] is False
    assert before == tm._MODELS
    assert _finish()["success"] is True
