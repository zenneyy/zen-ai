"""The append-only event the ledger records, and the event kinds it knows.

The research ledger is event-sourced: nothing mutates a stored object in place.
Every change is a new :class:`LedgerEvent` appended to the log, and the current
state of any object is the *fold* of the events about it, in order. That is what
makes a killed-and-resumed run reconstruct identical state — the log is replayed
— and what makes concurrent writes safe: two appends are serialised, never a
lost update.

An event names the object it concerns (``object_type`` + ``object_id``), the
``object_version`` it produces (1 for the creating event, then monotonically up),
its provenance (``agent_id`` / ``task_id``), and an opaque ``payload`` carrying
the typed object's fields. The ``kind`` is advisory colour for the reader; the
fold is driven by ``object_type`` and ``object_version``.

Everything here is generic: the event knows nothing about vulnerability classes,
only about *objects changing over time*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from zen.tools.ledger.objects import utc_now


__all__ = [
    "AMENDMENT_APPENDED",
    "COVERAGE_RECORDED",
    "EVIDENCE_RECORDED",
    "FINDING_CONFIRMED",
    "FINDING_RECORDED",
    "HYPOTHESIS_ASSERTED",
    "MODEL_SAVED",
    "NOTE_DELETED",
    "NOTE_RECORDED",
    "SURFACE_OBSERVED",
    "VERDICT_RECORDED",
    "LedgerEvent",
]

# Object types the ledger projects. One projection per type.
OBJECT_THREAT_MODEL = "threat_model"
OBJECT_SURFACE = "surface_node"
OBJECT_HYPOTHESIS = "hypothesis"
OBJECT_COVERAGE = "coverage_cell"
OBJECT_EVIDENCE = "evidence"
OBJECT_FINDING = "finding"
OBJECT_VERDICT = "validator_verdict"
OBJECT_NOTE = "note"

# Event kinds — human-readable colour for the log. The fold is driven by
# object_type + object_version, so these never have to be exhaustive; a new kind
# on a known object type projects without any change to the fold.
MODEL_SAVED = "model_saved"
AMENDMENT_APPENDED = "amendment_appended"
SURFACE_OBSERVED = "surface_observed"
HYPOTHESIS_ASSERTED = "hypothesis_asserted"
COVERAGE_RECORDED = "coverage_recorded"
EVIDENCE_RECORDED = "evidence_recorded"
FINDING_RECORDED = "finding_recorded"
FINDING_CONFIRMED = "finding_confirmed"
VERDICT_RECORDED = "verdict_recorded"
NOTE_RECORDED = "note_recorded"
NOTE_DELETED = "note_deleted"


@dataclass(frozen=True)
class LedgerEvent:
    """One immutable entry in the append-only research log.

    ``seq`` is the store-wide monotonic order (assigned on append); replaying
    events in ``seq`` order reconstructs every projection. ``object_version`` is
    the per-object version this event produces, which the optimistic-concurrency
    check reads: an append that expects a stale version is rejected before it is
    written.
    """

    seq: int
    event_id: str
    kind: str
    object_type: str
    object_id: str
    object_version: int
    payload: dict[str, Any]
    agent_id: str = ""
    task_id: str = ""
    at: str = field(default_factory=utc_now)

    def as_row(self) -> dict[str, Any]:
        """The event as a flat, JSON-serialisable row (for the SQLite log)."""
        return {
            "seq": self.seq,
            "event_id": self.event_id,
            "at": self.at,
            "kind": self.kind,
            "object_type": self.object_type,
            "object_id": self.object_id,
            "object_version": self.object_version,
            "agent_id": self.agent_id,
            "task_id": self.task_id,
            "payload": self.payload,
        }
