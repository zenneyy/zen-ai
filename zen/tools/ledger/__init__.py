"""The event-sourced research ledger (Phase 2, item 2.1).

An append-only, provenance-bearing store of the run's typed research objects —
surfaces, hypotheses, evidence, coverage, findings, and the verdicts that confirm
them — backed by a single local SQLite event log and resumable by replay. It is
the typed substrate the Phase-1 gates query instead of re-parsing prose, and the
socket section 2.2's validator verdicts plug into: a finding is unreachable in
``confirmed`` without a recorded, passing, re-executable verdict.

See :class:`~zen.tools.ledger.store.ResearchLedger` for the store itself,
:mod:`~zen.tools.ledger.objects` for the typed records, and
:mod:`~zen.tools.ledger.runtime` for the run-scoped singleton the tools reach.
"""

from __future__ import annotations

from zen.tools.ledger.objects import (
    CoverageCell,
    Evidence,
    EvidenceReplay,
    Finding,
    Hypothesis,
    Note,
    SurfaceNode,
    ValidatorVerdict,
    evidence_hash,
)
from zen.tools.ledger.runtime import (
    get_ledger,
    hydrate_ledger,
    reset_ledger,
    set_ledger,
)
from zen.tools.ledger.store import (
    DanglingEvidenceError,
    LedgerError,
    ResearchLedger,
    StaleVersionError,
    VerdictError,
)


__all__ = [
    "CoverageCell",
    "DanglingEvidenceError",
    "Evidence",
    "EvidenceReplay",
    "Finding",
    "Hypothesis",
    "LedgerError",
    "Note",
    "ResearchLedger",
    "StaleVersionError",
    "SurfaceNode",
    "ValidatorVerdict",
    "VerdictError",
    "evidence_hash",
    "get_ledger",
    "hydrate_ledger",
    "reset_ledger",
    "set_ledger",
]
