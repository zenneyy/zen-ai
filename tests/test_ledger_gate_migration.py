"""The Phase-1 gates, migrated to query the research ledger (item 2.1 step 6).

Each gate here is exercised on the *object-backed* path: an architecture is
registered, the dict architecture store is then cleared, and the gate is driven
with only the ledger holding surfaces — so a passing assertion proves the gate
read the ledger's typed :class:`SurfaceNode`s / :class:`Hypothesis` rows, not the
prose. The rejections and their field-level messages are the same ones the
pre-ledger gates produced; the migration preserves behavior, it does not relax
the gates.

Everything is class-agnostic: the fixtures describe a generic multi-stage service.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

import zen.tools.command_log.tools as cmd_tools
import zen.tools.detected_stack.tools as stack_tools
import zen.tools.threat_model.tools as tm_tools
from zen.tools.finish.tool import _undisposed_hypotheses_across_run
from zen.tools.ledger import ResearchLedger, set_ledger
from zen.tools.threat_model.implied_classes import implied_classes


if TYPE_CHECKING:
    from collections.abc import Iterator

TARGET = "https://app.example.test"


@pytest.fixture()
def ledger_run() -> Iterator[ResearchLedger]:
    """A fresh ledger installed as the run's, with the dict stores emptied."""
    store = ResearchLedger(":memory:")
    set_ledger(store)
    tm_tools._MODELS.clear()
    tm_tools._store_path = None
    stack_tools._DETECTED_ARCHITECTURE.clear()
    stack_tools._arch_store_path = None
    cmd_tools._COMMAND_LOG.clear()
    cmd_tools._store_path = None
    try:
        yield store
    finally:
        set_ledger(None)
        tm_tools._MODELS.clear()
        stack_tools._DETECTED_ARCHITECTURE.clear()
        cmd_tools._COMMAND_LOG.clear()
        store.close()


def _register_only_in_ledger(store: ResearchLedger, hops: list[dict[str, str]]) -> None:
    """Register an architecture, then drop it from the dict store.

    What remains is the ledger's typed surfaces alone, so a gate that still fires
    can only have read them — the object-backed path, proven by construction.
    """
    stack_tools._register_architecture_impl(TARGET, hops=hops, scan_targets=[TARGET])
    stack_tools._DETECTED_ARCHITECTURE.clear()
    assert store.has_surfaces()


def _dismissals(hops: list[dict[str, str]]) -> str:
    implied = implied_classes({TARGET: hops})
    if not implied:
        return ""
    lines = ["", "## Dismissed Implied Classes", ""]
    lines += [
        f"- vuln_class: {name} | reason: out of scope for this fixture"
        for name in sorted(implied)
    ]
    return "\n".join(lines) + "\n"


def _model(*, hypotheses: str, dismissals: str = "") -> str:
    return f"""# Threat Model

## Overview
A multi-stage service. Product code lives in `app/`; tooling is not deployed.

## Architecture
Requests traverse an edge proxy, then the application, then internal services.

## Trust Boundaries and Assumptions
Untrusted clients reach the application through the edge. Internal services
trust the forwarded identity established at the edge.

## Observations
The public application surface is attacker-reachable; internal services are
reached only through the application's server-side calls.

## Hypotheses
{hypotheses}
{dismissals}
## Severity Calibration
Critical: cross-boundary compromise. High: data exposure. Medium: verbose errors.
"""


_DISPOSED_HYP = (
    "- id: H1 | basis: assumed | mechanism: a client abuses application logic | "
    "predicted_observable: an unauthorized state change | state: blocked | "
    "disposition: deferred | disposition_reason: needs credentials this engagement lacks"
)
_OPEN_HYP = (
    "- id: H1 | basis: assumed | mechanism: a client abuses application logic | "
    "predicted_observable: an unauthorized state change | state: open"
)


# ── indirect-service enumeration gate (reads SurfaceNode.reachability) ────────


def test_indirect_service_gate_fires_from_ledger_surfaces(ledger_run: ResearchLedger) -> None:
    """A backend reached only through the application, with no discovery pass, is
    flagged by its name — read from the ledger's surface reachability alone."""
    _register_only_in_ledger(
        ledger_run,
        [
            {"name": "edge-service", "role": "entry point"},
            {"name": "app-service", "role": "application framework"},
            {"name": "internal-backend", "role": "backend service"},
        ],
    )
    result = tm_tools._save_impl(
        TARGET, _model(hypotheses=_DISPOSED_HYP), "root", scan_targets=[TARGET]
    )
    assert result["success"] is False
    assert "indirectly-reached service" in result["error"]
    assert "internal-backend" in result["error"]


def test_indirect_service_gate_passes_from_ledger_when_discovery_ran(
    ledger_run: ResearchLedger,
) -> None:
    hops = [
        {"name": "edge-service", "role": "entry point"},
        {"name": "app-service", "role": "application framework"},
        {"name": "internal-backend", "role": "backend service"},
    ]
    _register_only_in_ledger(ledger_run, hops)
    cmd_tools.record_command("feroxbuster -u http://internal-backend:8080 -w words.txt")
    result = tm_tools._save_impl(
        TARGET,
        _model(hypotheses=_DISPOSED_HYP, dismissals=_dismissals(hops)),
        "root",
        scan_targets=[TARGET],
    )
    assert result["success"] is True, result


# ── architecture-implied-classes completeness gate (query over objects) ──────


def test_completeness_gate_fires_from_ledger_surfaces(ledger_run: ResearchLedger) -> None:
    """An architecture-implied class that is neither hypothesized nor dismissed is
    rejected — with the implied classes computed from the ledger's surfaces."""
    _register_only_in_ledger(ledger_run, [{"name": "app", "role": "application handler"}])
    result = tm_tools._save_impl(
        TARGET, _model(hypotheses=_DISPOSED_HYP), "root", scan_targets=[TARGET]
    )
    assert result["success"] is False
    assert "architecture-implied vulnerability class" in result["error"]


def test_completeness_gate_passes_when_every_implied_class_is_dismissed(
    ledger_run: ResearchLedger,
) -> None:
    hops = [{"name": "app", "role": "application handler"}]
    _register_only_in_ledger(ledger_run, hops)
    result = tm_tools._save_impl(
        TARGET,
        _model(hypotheses=_DISPOSED_HYP, dismissals=_dismissals(hops)),
        "root",
        scan_targets=[TARGET],
    )
    assert result["success"] is True, result


# ── basis gate (operates on Hypothesis objects) ──────────────────────────────


def test_basis_gate_still_rejects_and_nothing_enters_the_ledger(
    ledger_run: ResearchLedger,
) -> None:
    """A hypothesis missing its basis is rejected naming it, and the rejected
    model never enters the ledger — the gate protects the object store too."""
    _register_only_in_ledger(ledger_run, [{"name": "app", "role": "application handler"}])
    bad = _model(
        hypotheses="- id: H1 | mechanism: m | predicted_observable: o | state: open",
        dismissals=_dismissals([{"name": "app", "role": "application handler"}]),
    )
    result = tm_tools._save_impl(TARGET, bad, "root", scan_targets=[TARGET])
    assert result["success"] is False
    assert "H1" in result["error"]
    assert "basis" in result["error"]
    assert ledger_run.get_model_view(TARGET) is None  # not stored


# ── closure gate (queries typed Hypothesis rows) ─────────────────────────────


def test_closure_gate_blocks_an_undisposed_open_hypothesis_from_the_ledger(
    ledger_run: ResearchLedger,
) -> None:
    hops = [{"name": "app", "role": "application handler"}]
    _register_only_in_ledger(ledger_run, hops)
    assert tm_tools._save_impl(
        TARGET, _model(hypotheses=_OPEN_HYP, dismissals=_dismissals(hops)), "root",
        scan_targets=[TARGET],
    )["success"] is True
    # The closure gate reads the ledger's typed hypotheses: H1 is open, undisposed.
    assert _undisposed_hypotheses_across_run() == ["H1"]


def test_closure_gate_lets_a_disposed_hypothesis_pass_from_the_ledger(
    ledger_run: ResearchLedger,
) -> None:
    hops = [{"name": "app", "role": "application handler"}]
    _register_only_in_ledger(ledger_run, hops)
    assert tm_tools._save_impl(
        TARGET, _model(hypotheses=_DISPOSED_HYP, dismissals=_dismissals(hops)), "root",
        scan_targets=[TARGET],
    )["success"] is True
    assert _undisposed_hypotheses_across_run() == []


# ── the document contract (the view over the ledger) ─────────────────────────


def test_missing_section_still_fires_over_the_ledger(ledger_run: ResearchLedger) -> None:
    _register_only_in_ledger(ledger_run, [{"name": "app", "role": "application handler"}])
    thin = _model(hypotheses=_DISPOSED_HYP).replace("## Severity Calibration", "## Notes")
    result = tm_tools._save_impl(TARGET, thin, "root", scan_targets=[TARGET])
    assert result["success"] is False
    assert "missing required section" in result["error"]
    assert "severity calibration" in result["error"]


def test_saved_model_round_trips_through_the_ledger_view(ledger_run: ResearchLedger) -> None:
    hops = [{"name": "app", "role": "application handler"}]
    _register_only_in_ledger(ledger_run, hops)
    body = _model(hypotheses=_DISPOSED_HYP, dismissals=_dismissals(hops))
    assert tm_tools._save_impl(TARGET, body, "recon", scan_targets=[TARGET])["success"] is True
    # The dict store is irrelevant here — the view is served from the ledger.
    tm_tools._MODELS.clear()
    got = tm_tools._get_impl(TARGET, scan_targets=[TARGET])
    assert got["found"] is True
    assert "multi-stage service" in got["content"]
    # The hypotheses are queryable as typed objects (keyed by the resolved identity).
    assert [h.id for h in ledger_run.get_hypotheses()] == ["H1"]


def test_amendment_content_is_not_lost_when_a_later_save_overwrites(
    ledger_run: ResearchLedger,
) -> None:
    """The old overwrite-clears-amendments hazard, over the ledger: a save folds
    the outstanding amendment forward (nothing lost) and the amendment event
    stays on the append-only log."""
    hops = [{"name": "app", "role": "application handler"}]
    _register_only_in_ledger(ledger_run, hops)
    body = _model(hypotheses=_DISPOSED_HYP, dismissals=_dismissals(hops))
    tm_tools._save_impl(TARGET, body, "root", scan_targets=[TARGET])
    tm_tools._amend_impl(
        TARGET,
        "The internal services are reachable without the forwarded identity; treat them "
        "as attacker-reachable (see app/router.py).",
        "agent-a",
        scan_targets=[TARGET],
    )
    # A fresh save without having seen the amendment.
    result = tm_tools._save_impl(
        TARGET, body.replace("multi-stage service", "multi-stage platform"), "root",
        scan_targets=[TARGET],
    )
    assert result["success"] is True
    assert result["amendments_folded"] == 1
    got = tm_tools._get_impl(TARGET, scan_targets=[TARGET])
    assert "app/router.py" in got["content"]  # the amendment text survived
