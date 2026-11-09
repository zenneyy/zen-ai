"""The run-scoped :class:`ResearchLedger` singleton, and its resume hook.

One ledger belongs to one scan. The tools and gates reach it through
:func:`get_ledger`; the runner installs it once per run with
:func:`hydrate_ledger`, pointing it at the run's state directory so a resumed
scan replays the same event log and reconstructs identical state. When no ledger
is installed — a unit test exercising a tool in isolation, say — :func:`get_ledger`
returns ``None`` and every caller falls back to its prior, dict-backed path, so
the ledger is additive and never a hard dependency.

The ledger file lives under the run's own state directory (``research_ledger.db``),
so it is a single local store the sandbox owns: no external database, no network,
and nothing shared with a different scan.
"""

from __future__ import annotations

import logging
import threading
from typing import TYPE_CHECKING

from zen.tools.ledger.store import ResearchLedger


if TYPE_CHECKING:
    from pathlib import Path


logger = logging.getLogger(__name__)

_LEDGER_FILENAME = "research_ledger.db"

_lock = threading.RLock()
_ledger: ResearchLedger | None = None


def get_ledger() -> ResearchLedger | None:
    """The current run's ledger, or ``None`` when none is installed."""
    with _lock:
        return _ledger


def set_ledger(ledger: ResearchLedger | None) -> None:
    """Install (or clear) the run-scoped ledger. Tests use this directly."""
    global _ledger  # noqa: PLW0603
    with _lock:
        _ledger = ledger


def hydrate_ledger(state_dir: Path) -> ResearchLedger:
    """Open the run's ledger and replay its event log (the resume path).

    Called by the runner alongside the other per-run stores. Opening the SQLite
    file replays whatever events a prior, killed run already wrote, so a resumed
    scan starts from exactly the state it left — the event log is the single
    durable record, nothing lives only in memory.
    """
    state_dir.mkdir(parents=True, exist_ok=True)
    ledger = ResearchLedger(state_dir / _LEDGER_FILENAME)
    set_ledger(ledger)
    logger.info(
        "research ledger hydrated from %s (%d event(s))",
        state_dir / _LEDGER_FILENAME,
        ledger.event_count(),
    )
    return ledger


def reset_ledger() -> None:
    """Clear and detach the ledger (test isolation / a fresh run)."""
    with _lock:
        if _ledger is not None:
            try:
                _ledger.reset()
            except Exception:  # noqa: BLE001 - best-effort teardown
                logger.debug("ledger reset failed during teardown", exc_info=True)
    set_ledger(None)
