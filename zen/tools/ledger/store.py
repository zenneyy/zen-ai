"""The event-sourced research ledger: an append-only store of typed objects.

:class:`ResearchLedger` is the run's single source of truth for its structured
research state — surfaces, hypotheses, evidence, coverage, findings, and the
verdicts that confirm them. It is **event-sourced**: callers never mutate a
stored object, they append an event, and the current state of any object is the
fold of its events. Three properties fall out of that discipline, and each is a
requirement of this section:

* **Append-only, no lost updates.** Concurrent writers from parallel hunters are
  serialised; an amendment is never clobbered by a later save. The generalised
  guard is *optimistic concurrency*: a write that declares the version it read
  (``expected_version``) is rejected with :class:`StaleVersionError` if the
  object moved on since, naming the object and both versions — rather than
  silently overwriting.
* **Resumable from the log.** A killed-and-resumed run reconstructs identical
  state by replaying the event log (:meth:`replay`); nothing lives only in
  memory. The log is a single local SQLite file the sandbox owns — no external
  database, no network.
* **Provenance-bearing, re-checkable support.** :class:`Evidence` carries the
  tool-call ids and raw-output hashes that produced it and a re-executable
  descriptor; a :class:`Finding` may cite only evidence actually recorded here
  (a dangling reference is rejected), and it cannot be carried to ``confirmed``
  without a recorded, passing :class:`ValidatorVerdict`. That last pair is the
  socket section 2.2's validators plug into.

Everything stored is class-agnostic — the ledger reasons about *objects changing
over time*, never about any vulnerability class.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from typing import TYPE_CHECKING, Any

from pydantic import BaseModel

from zen.tools.ledger.events import (
    AMENDMENT_APPENDED,
    COVERAGE_RECORDED,
    EVIDENCE_RECORDED,
    FINDING_CONFIRMED,
    FINDING_RECORDED,
    HYPOTHESIS_ASSERTED,
    MODEL_SAVED,
    NOTE_DELETED,
    NOTE_RECORDED,
    OBJECT_COVERAGE,
    OBJECT_EVIDENCE,
    OBJECT_FINDING,
    OBJECT_HYPOTHESIS,
    OBJECT_NOTE,
    OBJECT_SURFACE,
    OBJECT_THREAT_MODEL,
    OBJECT_VERDICT,
    SURFACE_OBSERVED,
    VERDICT_RECORDED,
    LedgerEvent,
)
from zen.tools.ledger.objects import (
    CoverageCell,
    Evidence,
    Finding,
    Hypothesis,
    Note,
    SurfaceNode,
    ValidatorVerdict,
    utc_now,
)
from zen.tools.ledger.projection import surfaces_from_hops


if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from pathlib import Path


logger = logging.getLogger(__name__)


__all__ = [
    "DanglingEvidenceError",
    "LedgerError",
    "ResearchLedger",
    "StaleVersionError",
    "VerdictError",
]


class LedgerError(RuntimeError):
    """Base class for a ledger write the store refuses, so callers can catch one."""


class StaleVersionError(LedgerError):
    """A write declared a version the object has since moved past.

    Names the object and both versions so the caller can re-read and retry
    instead of clobbering a concurrent writer's change.
    """

    def __init__(self, object_type: str, object_id: str, *, seen: int, current: int) -> None:
        self.object_type = object_type
        self.object_id = object_id
        self.seen = seen
        self.current = current
        super().__init__(
            f"stale write to {object_type} {object_id!r}: you based it on version {seen}, but "
            f"the current version is {current}. Another agent changed it since you read it. "
            "Re-read the object and re-apply your change onto the current version rather than "
            "overwriting it."
        )


class DanglingEvidenceError(LedgerError):
    """A finding cited evidence ids the ledger never recorded.

    A finding's support must be re-checkable, so it may reference only evidence
    that was actually captured and recorded. The message names the dangling ids.
    """

    def __init__(self, finding_id: str, missing: Sequence[str]) -> None:
        self.finding_id = finding_id
        self.missing = list(missing)
        super().__init__(
            f"finding {finding_id!r} cites evidence that was never recorded: "
            f"{sorted(set(missing))}. A finding may reference only evidence captured and "
            "recorded in the ledger (so its support can be replayed). Record the evidence "
            "first, or drop the dangling reference."
        )


class VerdictError(LedgerError):
    """A confirmation lacked a recorded, passing, attributable verdict.

    Confirming a finding requires a :class:`ValidatorVerdict` that exists, passed,
    and names its author. The message states which of those failed.
    """


class ResearchLedger:
    """An append-only, event-sourced store of the run's typed research objects.

    Backed by a single local SQLite file (or ``:memory:`` for ephemeral use).
    The event log is authoritative; the in-memory projections are the fold of it
    and are rebuilt by :meth:`replay` on open, which is what makes a resumed run
    reconstruct identical state.
    """

    def __init__(self, path: str | Path = ":memory:") -> None:
        self._path = str(path)
        self._lock = threading.RLock()
        self._conn = sqlite3.connect(self._path, check_same_thread=False)
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT NOT NULL,
                at TEXT NOT NULL,
                kind TEXT NOT NULL,
                object_type TEXT NOT NULL,
                object_id TEXT NOT NULL,
                object_version INTEGER NOT NULL,
                agent_id TEXT NOT NULL DEFAULT '',
                task_id TEXT NOT NULL DEFAULT '',
                payload TEXT NOT NULL
            )
            """
        )
        self._conn.commit()
        # Projections: object_type -> object_id -> {"version": int, "state": Any}.
        # ``state`` is the typed object for most types, and the folded view dict
        # for the threat-model document.
        self._proj: dict[str, dict[str, dict[str, Any]]] = {}
        self.replay()

    # ── low-level append + replay ────────────────────────────────────────────

    def _current_version(self, object_type: str, object_id: str) -> int:
        bucket = self._proj.get(object_type, {})
        entry = bucket.get(object_id)
        return int(entry["version"]) if entry else 0

    def append_event(
        self,
        *,
        kind: str,
        object_type: str,
        object_id: str,
        payload: dict[str, Any],
        expected_version: int | None = None,
        agent_id: str = "",
        task_id: str = "",
    ) -> LedgerEvent:
        """Append one event, enforcing optimistic concurrency, and fold it in.

        ``expected_version`` is the version the caller based the write on. When it
        is given and does not match the object's current version, the write is
        rejected with :class:`StaleVersionError` — the generalised no-lost-update
        guard. ``None`` skips the check (a blind write, e.g. the first creation).
        """
        with self._lock:
            current = self._current_version(object_type, object_id)
            if expected_version is not None and expected_version != current:
                raise StaleVersionError(
                    object_type, object_id, seen=expected_version, current=current
                )
            version = current + 1
            event_id = uuid.uuid4().hex
            cursor = self._conn.execute(
                "INSERT INTO events (event_id, at, kind, object_type, object_id, "
                "object_version, agent_id, task_id, payload) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event_id,
                    utc_now(),
                    kind,
                    object_type,
                    object_id,
                    version,
                    agent_id,
                    task_id,
                    json.dumps(payload, ensure_ascii=False, default=str),
                ),
            )
            self._conn.commit()
            event = LedgerEvent(
                seq=int(cursor.lastrowid or 0),
                event_id=event_id,
                kind=kind,
                object_type=object_type,
                object_id=object_id,
                object_version=version,
                payload=payload,
                agent_id=agent_id,
                task_id=task_id,
            )
            self._fold(event)
            return event

    def replay(self) -> None:
        """Rebuild every projection from the event log, in order.

        This is the resume path: on open, the in-memory projections are empty and
        the full log is folded back, so a resumed run starts from exactly the
        state the killed run left — nothing is kept only in memory.
        """
        with self._lock:
            self._proj = {}
            for row in self._conn.execute(
                "SELECT seq, event_id, at, kind, object_type, object_id, object_version, "
                "agent_id, task_id, payload FROM events ORDER BY seq"
            ):
                event = LedgerEvent(
                    seq=row[0],
                    event_id=row[1],
                    at=row[2],
                    kind=row[3],
                    object_type=row[4],
                    object_id=row[5],
                    object_version=row[6],
                    agent_id=row[7],
                    task_id=row[8],
                    payload=json.loads(row[9]),
                )
                self._fold(event)

    def _fold(self, event: LedgerEvent) -> None:
        """Apply one event to the projection for its object type."""
        bucket = self._proj.setdefault(event.object_type, {})
        if event.object_type == OBJECT_THREAT_MODEL:
            state = self._fold_threat_model(bucket.get(event.object_id), event)
        else:
            # Every other object type stores its latest payload as the state; the
            # typed object is reconstructed lazily by the readers.
            state = event.payload
        bucket[event.object_id] = {"version": event.object_version, "state": state}

    @staticmethod
    def _fold_threat_model(
        prior: dict[str, Any] | None, event: LedgerEvent
    ) -> dict[str, Any]:
        """Fold a model-saved / amendment event into the document view.

        A ``model_saved`` resets the document (content, author, and an empty
        amendment list — any outstanding amendments were already folded into the
        saved body by the tool). An ``amendment_appended`` appends to the list.
        The result mirrors the shape the threat-model store kept, so the rendered
        view is byte-for-byte what the pre-ledger path returned.
        """
        prior_state: dict[str, Any] = dict(prior["state"]) if prior else {}
        if event.kind == AMENDMENT_APPENDED:
            amendments = list(prior_state.get("amendments", []))
            amendments.append(
                {
                    "at": event.payload.get("at", ""),
                    "by": event.payload.get("by", ""),
                    "content": event.payload.get("content", ""),
                }
            )
            prior_state["amendments"] = amendments
            return prior_state
        # model_saved (or any document-replacing event)
        return {
            "content": event.payload.get("content", ""),
            "written_by": event.payload.get("written_by"),
            "written_at": event.payload.get("written_at", ""),
            "hypotheses": event.payload.get("hypotheses", []),
            "amendments": [],
        }

    # ── threat-model document (view over events) ─────────────────────────────

    def record_model(
        self,
        identity: str,
        *,
        content: str,
        written_by: str | None,
        written_at: str,
        hypotheses: Iterable[Hypothesis] = (),
        expected_version: int | None = None,
        agent_id: str = "",
    ) -> int:
        """Record a full threat-model document as a ``model_saved`` event.

        Returns the new document version. The parsed hypotheses are carried in
        the event payload (and projected as typed :class:`Hypothesis` rows), so
        the gates query objects instead of re-parsing the prose each time.
        """
        payload = {
            "content": content,
            "written_by": written_by,
            "written_at": written_at,
            "hypotheses": [h.model_dump() for h in hypotheses],
        }
        event = self.append_event(
            kind=MODEL_SAVED,
            object_type=OBJECT_THREAT_MODEL,
            object_id=identity,
            payload=payload,
            expected_version=expected_version,
            agent_id=agent_id,
        )
        # Project the hypotheses as their own object so the closure/implied-class
        # gates can query typed Hypothesis rows per target.
        self._store_payload(
            OBJECT_HYPOTHESIS,
            identity,
            {"hypotheses": payload["hypotheses"]},
            kind=HYPOTHESIS_ASSERTED,
            agent_id=agent_id,
        )
        return event.object_version

    def record_amendment(
        self,
        identity: str,
        *,
        by: str | None,
        at: str,
        content: str,
        expected_version: int | None = None,
        agent_id: str = "",
    ) -> int:
        """Append an amendment to a document as an ``amendment_appended`` event."""
        event = self.append_event(
            kind=AMENDMENT_APPENDED,
            object_type=OBJECT_THREAT_MODEL,
            object_id=identity,
            payload={"by": by, "at": at, "content": content},
            expected_version=expected_version,
            agent_id=agent_id,
        )
        return event.object_version

    def get_model_view(self, identity: str) -> dict[str, Any] | None:
        """The rendered document view for a target, or ``None`` if none saved.

        A projection of the event log: the latest saved body folded with every
        amendment appended since. ``content`` plus, when present, ``amendments``.
        """
        with self._lock:
            entry = self._proj.get(OBJECT_THREAT_MODEL, {}).get(identity)
            if entry is None:
                return None
            state = entry["state"]
            content = str(state.get("content") or "")
            if not content.strip():
                return None
            view: dict[str, Any] = {
                "content": content,
                "written_by": state.get("written_by"),
                "written_at": state.get("written_at", ""),
                "version": entry["version"],
            }
            amendments = list(state.get("amendments", []))
            if amendments:
                view["amendments"] = amendments
            return view

    def model_version(self, identity: str) -> int:
        """Current version of a target's document (0 if none), for concurrency."""
        with self._lock:
            return self._current_version(OBJECT_THREAT_MODEL, identity)

    def model_identities(self) -> list[str]:
        """Target identities that have a saved document (for the closure gate)."""
        with self._lock:
            return list(self._proj.get(OBJECT_THREAT_MODEL, {}))

    def has_models(self) -> bool:
        """Whether any document has been saved (gate: ledger vs fallback)."""
        with self._lock:
            return bool(self._proj.get(OBJECT_THREAT_MODEL))

    def get_hypotheses(self, identity: str | None = None) -> list[Hypothesis]:
        """Typed hypotheses for one target, or across every model when ``None``."""
        out: list[Hypothesis] = []
        with self._lock:
            bucket = self._proj.get(OBJECT_HYPOTHESIS, {})
            ids = [identity] if identity is not None else list(bucket)
            for oid in ids:
                entry = bucket.get(oid)
                if entry is None:
                    continue
                out.extend(
                    _rebuild(Hypothesis, raw)
                    for raw in entry["state"].get("hypotheses", [])
                )
        return out

    # ── surfaces (the architecture, as typed SurfaceNodes) ───────────────────

    def record_architecture(
        self,
        identity: str,
        hops: Sequence[dict[str, str]],
        *,
        expected_version: int | None = None,
        agent_id: str = "",
    ) -> list[SurfaceNode]:
        """Record a target's ordered request path as typed :class:`SurfaceNode`s.

        Mirrors the architecture store's whole-list replacement: each
        ``register_architecture`` records the full ordered hop list, projected to
        typed surfaces whose structural kind, reachability, and trust context are
        derived once from the same ``name``/``role`` text the mapping reads.
        """
        nodes = surfaces_from_hops(identity, hops)
        self.append_event(
            kind=SURFACE_OBSERVED,
            object_type=OBJECT_SURFACE,
            object_id=identity,
            payload={"surfaces": [n.model_dump() for n in nodes]},
            expected_version=expected_version,
            agent_id=agent_id,
        )
        return nodes

    def get_surface_nodes(self, identity: str | None = None) -> list[SurfaceNode]:
        """Typed surfaces for one target, or across every target when ``None``."""
        out: list[SurfaceNode] = []
        with self._lock:
            bucket = self._proj.get(OBJECT_SURFACE, {})
            ids = [identity] if identity is not None else list(bucket)
            for oid in ids:
                entry = bucket.get(oid)
                if entry is None:
                    continue
                out.extend(
                    _rebuild(SurfaceNode, raw)
                    for raw in entry["state"].get("surfaces", [])
                )
        return out

    def architecture_mapping(self) -> dict[str, list[dict[str, str]]]:
        """``identity -> ordered hop dicts`` reconstructed from the surfaces.

        Hands the architecture-implied-classes mapping exactly the ``{name,
        role}`` hop shape it consumed before the ledger existed, so the gate's
        result is behavior-equivalent whether it reads the ledger or the store.
        """
        out: dict[str, list[dict[str, str]]] = {}
        for identity in self._surface_identities():
            nodes = sorted(self.get_surface_nodes(identity), key=lambda n: n.order_index)
            out[identity] = [n.as_hop() for n in nodes]
        return out

    def _surface_identities(self) -> list[str]:
        with self._lock:
            return list(self._proj.get(OBJECT_SURFACE, {}))

    def has_surfaces(self) -> bool:
        """Whether any architecture has been recorded (gate: ledger vs fallback)."""
        with self._lock:
            return bool(self._proj.get(OBJECT_SURFACE))

    # ── coverage ─────────────────────────────────────────────────────────────

    def record_coverage_cell(
        self, cell: CoverageCell, *, expected_version: int | None = None, agent_id: str = ""
    ) -> CoverageCell:
        """Record (or update, by id) one coverage cell."""
        self.append_event(
            kind=COVERAGE_RECORDED,
            object_type=OBJECT_COVERAGE,
            object_id=cell.id,
            payload=cell.model_dump(),
            expected_version=expected_version,
            agent_id=agent_id or cell.agent_id,
        )
        return cell

    def get_coverage_cells(self) -> list[CoverageCell]:
        return [
            _rebuild(CoverageCell, entry["state"])
            for entry in self._proj.get(OBJECT_COVERAGE, {}).values()
        ]

    # ── notes (free-text scratch, event-logged for resume) ───────────────────

    def record_note(self, note: Note, *, agent_id: str = "") -> Note:
        """Record (or update, by id) one free-text note."""
        self.append_event(
            kind=NOTE_RECORDED,
            object_type=OBJECT_NOTE,
            object_id=note.id,
            payload=note.model_dump(),
            agent_id=agent_id or note.agent_id,
        )
        return note

    def delete_note(self, note_id: str) -> None:
        """Mark a note deleted (an event, so the deletion is itself on the log)."""
        self.append_event(
            kind=NOTE_DELETED,
            object_type=OBJECT_NOTE,
            object_id=note_id,
            payload={"id": note_id, "deleted": True},
        )

    def get_notes(self) -> list[Note]:
        """Every note not marked deleted, as typed objects."""
        notes: list[Note] = []
        for entry in self._proj.get(OBJECT_NOTE, {}).values():
            state = entry["state"]
            if state.get("deleted"):
                continue
            notes.append(_rebuild(Note, state))
        return notes

    # ── evidence (provenance-bearing, re-executable) ─────────────────────────

    def record_evidence(
        self, evidence: Evidence, *, expected_version: int | None = None, agent_id: str = ""
    ) -> Evidence:
        """Record one captured piece of evidence with its provenance + replay."""
        self.append_event(
            kind=EVIDENCE_RECORDED,
            object_type=OBJECT_EVIDENCE,
            object_id=evidence.id,
            payload=evidence.model_dump(),
            expected_version=expected_version,
            agent_id=agent_id or evidence.agent_id,
            task_id=evidence.task_id,
        )
        return evidence

    def get_evidence(self, evidence_id: str) -> Evidence | None:
        with self._lock:
            entry = self._proj.get(OBJECT_EVIDENCE, {}).get(evidence_id)
        return _rebuild(Evidence, entry["state"]) if entry else None

    def known_evidence_ids(self) -> set[str]:
        """Every recorded evidence id — the set a finding's references resolve to."""
        with self._lock:
            return set(self._proj.get(OBJECT_EVIDENCE, {}))

    # ── findings + verdicts (the 2.2 socket) ─────────────────────────────────

    def record_finding(
        self, finding: Finding, *, expected_version: int | None = None, agent_id: str = ""
    ) -> Finding:
        """Record a finding candidate, rejecting any dangling evidence reference.

        The dangling-reference guard is the first half of the 2.2 socket: a
        finding may cite only evidence actually recorded, so its support is
        always re-checkable. A finding may not be *recorded* already-confirmed —
        confirmation goes through :meth:`confirm_finding`, which requires a
        verdict — so a recorded ``confirmed`` state with no recorded verdict is
        rejected here too.
        """
        missing = [eid for eid in finding.evidence_ids if eid not in self.known_evidence_ids()]
        if missing:
            raise DanglingEvidenceError(finding.id, missing)
        if finding.state == "confirmed":
            self._assert_confirmable(finding)
        self.append_event(
            kind=FINDING_RECORDED,
            object_type=OBJECT_FINDING,
            object_id=finding.id,
            payload=finding.model_dump(),
            expected_version=expected_version,
            agent_id=agent_id,
        )
        return finding

    def record_verdict(self, verdict: ValidatorVerdict) -> ValidatorVerdict:
        """Record a validator / reviewer verdict (passed or rejected)."""
        self.append_event(
            kind=VERDICT_RECORDED,
            object_type=OBJECT_VERDICT,
            object_id=verdict.id,
            payload=verdict.model_dump(),
            agent_id=verdict.author,
        )
        return verdict

    def get_verdict(self, verdict_id: str) -> ValidatorVerdict | None:
        with self._lock:
            entry = self._proj.get(OBJECT_VERDICT, {}).get(verdict_id)
        return _rebuild(ValidatorVerdict, entry["state"]) if entry else None

    def get_finding(self, finding_id: str) -> Finding | None:
        with self._lock:
            entry = self._proj.get(OBJECT_FINDING, {}).get(finding_id)
        return _rebuild(Finding, entry["state"]) if entry else None

    def list_findings(self) -> list[Finding]:
        return [
            _rebuild(Finding, entry["state"])
            for entry in self._proj.get(OBJECT_FINDING, {}).values()
        ]

    def confirm_finding(
        self, finding_id: str, verdict: ValidatorVerdict, *, agent_id: str = ""
    ) -> Finding:
        """Carry a recorded finding to ``confirmed`` behind a passing verdict.

        The second half of the 2.2 socket. The verdict is recorded, then the
        finding is promoted to ``confirmed`` with the verdict's id and author —
        but only if the verdict passed and names an author. A verdict that did
        not pass (including a reach-only rejection) cannot confirm a finding;
        :class:`VerdictError` is raised instead, so ``confirmed`` is reachable
        *only* through a passing, attributable, re-executable verdict.
        """
        with self._lock:
            finding = self.get_finding(finding_id)
            if finding is None:
                msg = f"no recorded finding {finding_id!r} to confirm"
                raise VerdictError(msg)
            if self.get_verdict(verdict.id) is None:
                self.record_verdict(verdict)
            self._assert_verdict_confirms(finding_id, verdict)
            current = self._current_version(OBJECT_FINDING, finding_id)
            confirmed = finding.model_copy(
                update={
                    "state": "confirmed",
                    "validator_verdict_id": verdict.id,
                    "verdict_author": verdict.author,
                }
            )
            self.append_event(
                kind=FINDING_CONFIRMED,
                object_type=OBJECT_FINDING,
                object_id=finding_id,
                payload=confirmed.model_dump(),
                expected_version=current,
                agent_id=agent_id or verdict.author,
            )
            return confirmed

    def _assert_confirmable(self, finding: Finding) -> None:
        """A finding recorded as ``confirmed`` must point at a passing verdict."""
        verdict = self.get_verdict(finding.validator_verdict_id)
        if verdict is None:
            msg = (
                f"finding {finding.id!r} is marked confirmed but its "
                f"validator_verdict_id {finding.validator_verdict_id!r} references no recorded "
                "verdict. A finding reaches confirmed only through a recorded validator verdict."
            )
            raise VerdictError(msg)
        self._assert_verdict_confirms(finding.id, verdict)

    @staticmethod
    def _assert_verdict_confirms(finding_id: str, verdict: ValidatorVerdict) -> None:
        if verdict.finding_id and verdict.finding_id != finding_id:
            msg = (
                f"verdict {verdict.id!r} was authored for finding {verdict.finding_id!r}, not "
                f"{finding_id!r}; a verdict confirms only the finding it validated."
            )
            raise VerdictError(msg)
        if not verdict.passed:
            reason = "it only proved the surface was reached (no oracle signal)" if (
                verdict.reach_only
            ) else "it did not pass"
            msg = (
                f"verdict {verdict.id!r} cannot confirm finding {finding_id!r}: {reason}. "
                "Confirmation requires a validator verdict whose re-executed evidence observed "
                "the oracle signal."
            )
            raise VerdictError(msg)
        if not verdict.author.strip():
            msg = (
                f"verdict {verdict.id!r} has no author; a confirmation must be attributable to "
                "the validator or reviewer that authored it."
            )
            raise VerdictError(msg)

    # ── bounded views (counter context rot) ──────────────────────────────────

    def scoped_view(
        self,
        *,
        agent_id: str | None = None,
        surface_ids: Iterable[str] | None = None,
        object_types: Iterable[str] | None = None,
        limit: int = 50,
    ) -> dict[str, list[dict[str, Any]]]:
        """A bounded slice of the ledger for one agent — not a whole-store dump.

        A hunter is handed its own surfaces and the hypotheses/findings that
        touch them, capped at ``limit`` per type, rather than every object in the
        run. The slice is the counter to context rot: an agent reasons over the
        state relevant to it, not the entire accumulated store.
        """
        wanted_surfaces = set(surface_ids) if surface_ids is not None else None
        types = set(object_types) if object_types is not None else {
            OBJECT_SURFACE,
            OBJECT_HYPOTHESIS,
            OBJECT_FINDING,
            OBJECT_EVIDENCE,
        }
        view: dict[str, list[dict[str, Any]]] = {}

        if OBJECT_SURFACE in types:
            surfaces = [
                n
                for n in self.get_surface_nodes()
                if wanted_surfaces is None or n.id in wanted_surfaces
            ]
            view[OBJECT_SURFACE] = [n.model_dump() for n in surfaces[:limit]]

        if OBJECT_HYPOTHESIS in types:
            hyps = self.get_hypotheses()
            if wanted_surfaces is not None:
                hyps = [
                    h
                    for h in hyps
                    if set(h.depends_on) & wanted_surfaces
                    or any(ref in wanted_surfaces for ref in h.supporting_evidence_ids)
                    or h.id in wanted_surfaces
                ]
            view[OBJECT_HYPOTHESIS] = [h.model_dump() for h in hyps[:limit]]

        if OBJECT_FINDING in types:
            findings = self.list_findings()
            if agent_id is not None:
                scoped = [f for f in findings if f.id in (wanted_surfaces or set())]
                findings = scoped or findings
            view[OBJECT_FINDING] = [f.model_dump() for f in findings[:limit]]

        if OBJECT_EVIDENCE in types:
            evidence = [
                self._proj[OBJECT_EVIDENCE][eid]["state"]
                for eid in list(self._proj.get(OBJECT_EVIDENCE, {}))[:limit]
            ]
            view[OBJECT_EVIDENCE] = evidence

        return view

    # ── lifecycle ────────────────────────────────────────────────────────────

    def event_count(self) -> int:
        with self._lock:
            return int(self._conn.execute("SELECT COUNT(*) FROM events").fetchone()[0])

    def reset(self) -> None:
        """Clear the log and every projection (test isolation / a fresh run)."""
        with self._lock:
            self._conn.execute("DELETE FROM events")
            self._conn.commit()
            self._proj = {}

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ── internals ────────────────────────────────────────────────────────────

    def _store_payload(
        self,
        object_type: str,
        object_id: str,
        payload: dict[str, Any],
        *,
        kind: str,
        agent_id: str = "",
    ) -> None:
        self.append_event(
            kind=kind,
            object_type=object_type,
            object_id=object_id,
            payload=payload,
            agent_id=agent_id,
        )


def _rebuild[M: BaseModel](model: type[M], raw: dict[str, Any]) -> M:
    """Reconstruct a typed object from a projected payload, tolerating old rows.

    Validation without a context skips the resolution validators (evidence-id
    membership, surface-ref resolution) — the objects were validated when first
    recorded, so a replay reconstructs their shape without re-resolving against
    live state that a resumed run may not have yet.
    """
    return model.model_validate(raw)
