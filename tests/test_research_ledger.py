"""The event-sourced research ledger (Phase 2, item 2.1).

These exercise the store itself — the typed objects, optimistic concurrency, the
append-only log, resume-by-replay, bounded views, and the evidence/finding/verdict
guards that are the socket section 2.2 plugs into. Everything here is
class-agnostic: the fixtures describe surfaces, evidence, candidates, and verdicts
in general terms, never a vulnerability class.
"""

from __future__ import annotations

import threading
from typing import TYPE_CHECKING

import pytest

from zen.tools.ledger import (
    CoverageCell,
    DanglingEvidenceError,
    Evidence,
    EvidenceReplay,
    Finding,
    Note,
    ResearchLedger,
    StaleVersionError,
    ValidatorVerdict,
    VerdictError,
    evidence_hash,
)
from zen.tools.ledger.events import AMENDMENT_APPENDED
from zen.tools.ledger.objects import Hypothesis


if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path


@pytest.fixture()
def ledger() -> Iterator[ResearchLedger]:
    store = ResearchLedger(":memory:")
    try:
        yield store
    finally:
        store.close()


# ── typed objects + provenance ───────────────────────────────────────────────


def test_architecture_projects_to_typed_surfaces_with_reachability(ledger: ResearchLedger) -> None:
    """A registered path becomes typed surfaces whose reachability marks which are
    reached only through an upstream component (the gate's indirect services)."""
    nodes = ledger.record_architecture(
        "t",
        [
            {"name": "edge", "role": "reverse proxy"},
            {"name": "app", "role": "application framework"},
            {"name": "internal-backend", "role": "backend service"},
        ],
    )
    by_name = {n.name: n for n in nodes}
    # The edge (infrastructure) and the primary application are edge-reachable;
    # the backend behind the application is reached only through a component.
    assert by_name["edge"].reachability == "publicly_reachable"
    assert by_name["app"].reachability == "publicly_reachable"
    assert by_name["internal-backend"].reachability == "reached_through_component"
    # Round-trips to the hop shape the implied-classes mapping consumes.
    assert ledger.architecture_mapping()["t"][2] == {
        "name": "internal-backend",
        "role": "backend service",
    }


def test_evidence_carries_its_provenance(ledger: ResearchLedger) -> None:
    """Evidence records the tool-call ids, raw-output hashes, and agent/task that
    produced it — so a finding's support is provenance-bearing and re-checkable."""
    body = "HTTP/1.1 200 OK\n\n<canary-bearing body>"
    ev = Evidence(
        id="e1",
        kind="proxy_exchange",
        tool_call_ids=["call-7"],
        raw_output_hashes=[evidence_hash(body)],
        evidence_refs=["101"],
        agent_id="hunter-3",
        task_id="task-9",
        replay=EvidenceReplay(medium="http", inputs={"method": "GET", "url": "http://x/y"}),
    )
    ledger.record_evidence(ev)
    stored = ledger.get_evidence("e1")
    assert stored is not None
    assert stored.tool_call_ids == ["call-7"]
    assert stored.raw_output_hashes == [evidence_hash(body)]
    assert stored.agent_id == "hunter-3" and stored.task_id == "task-9"
    assert stored.replay.medium == "http"
    assert "e1" in ledger.known_evidence_ids()


# ── optimistic concurrency + append-only ─────────────────────────────────────


def test_stale_write_is_rejected_naming_the_object_and_versions(ledger: ResearchLedger) -> None:
    ledger.record_model("t", content="x" * 20, written_by="root", written_at="t0")
    assert ledger.model_version("t") == 1
    with pytest.raises(StaleVersionError) as excinfo:
        # A writer that read version 0 tries to write again — it is stale now.
        ledger.record_model("t", content="y" * 20, written_by="root", written_at="t1",
                            expected_version=0)
    message = str(excinfo.value)
    assert "threat_model" in message
    assert "'t'" in message
    assert "version 0" in message
    assert "current version is 1" in message


def test_concurrent_amendments_are_serialized_and_none_is_lost(ledger: ResearchLedger) -> None:
    """Parallel hunters amending the same model: every amendment survives.

    This is the regression for the old overwrite-clears-amendments hazard made
    general — amendments are append-only events, so no writer clobbers another's.
    """
    ledger.record_model("t", content="base" * 20, written_by="root", written_at="t0")

    def amend(i: int) -> None:
        ledger.record_amendment("t", by=f"agent-{i}", at=f"t{i}", content=f"addendum {i}")

    threads = [threading.Thread(target=amend, args=(i,)) for i in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    view = ledger.get_model_view("t")
    assert view is not None
    assert len(view["amendments"]) == 12  # not one lost
    assert {a["content"] for a in view["amendments"]} == {f"addendum {i}" for i in range(12)}


def test_overwriting_a_model_cannot_erase_prior_amendment_events(
    ledger: ResearchLedger,
) -> None:
    """The old overwrite-clears-amendments data loss is structurally impossible:
    a later save resets the folded view, but the amendment EVENTS remain in the
    append-only log forever — nothing is erased, so nothing can be lost."""
    ledger.record_model("t", content="base" * 20, written_by="root", written_at="t0")
    ledger.record_amendment("t", by="agent-a", at="t1", content="correction A")
    before = ledger.event_count()

    # A fresh save (the old data-loss action) — it does not reduce the log.
    ledger.record_model("t", content="rewritten" * 10, written_by="root", written_at="t2")
    after = ledger.event_count()
    assert after > before  # strictly grew; the save appended, it did not erase

    amendment_events = ledger._conn.execute(
        "SELECT COUNT(*) FROM events WHERE kind = ?", (AMENDMENT_APPENDED,)
    ).fetchone()[0]
    assert amendment_events == 1  # the amendment event is still on the log


# ── resume by replay ─────────────────────────────────────────────────────────


def test_a_killed_and_resumed_run_reconstructs_identical_state(tmp_path: Path) -> None:
    db = tmp_path / "research_ledger.db"
    first = ResearchLedger(db)
    first.record_architecture("t", [{"name": "edge", "role": "proxy"}, {"name": "app"}])
    first.record_model(
        "t",
        content="model body " * 10,
        written_by="recon",
        written_at="t0",
        hypotheses=[Hypothesis(id="H1", basis="assumed", state="open")],
    )
    ev = Evidence(id="e1", kind="proxy_exchange", evidence_refs=["101"])
    first.record_evidence(ev)
    first.record_finding(Finding(id="f1", evidence_ids=["e1"]))
    snapshot = {
        "surfaces": [n.model_dump() for n in first.get_surface_nodes()],
        "model": first.get_model_view("t"),
        "hypotheses": [h.model_dump() for h in first.get_hypotheses()],
        "findings": [f.model_dump() for f in first.list_findings()],
        "evidence_ids": sorted(first.known_evidence_ids()),
    }
    first.close()

    # A separate process opening the same file replays the log from scratch.
    resumed = ResearchLedger(db)
    try:
        assert [n.model_dump() for n in resumed.get_surface_nodes()] == snapshot["surfaces"]
        assert resumed.get_model_view("t") == snapshot["model"]
        assert [h.model_dump() for h in resumed.get_hypotheses()] == snapshot["hypotheses"]
        assert [f.model_dump() for f in resumed.list_findings()] == snapshot["findings"]
        assert sorted(resumed.known_evidence_ids()) == snapshot["evidence_ids"]
    finally:
        resumed.close()


def test_scoped_view_is_a_bounded_slice_not_the_whole_store(ledger: ResearchLedger) -> None:
    ledger.record_architecture(
        "t", [{"name": "a"}, {"name": "b"}, {"name": "c"}, {"name": "d"}, {"name": "e"}]
    )
    # A hunter asking for one surface gets that slice, not every object.
    view = ledger.scoped_view(surface_ids={"t#2"}, object_types=["surface_node"], limit=50)
    assert set(view) == {"surface_node"}
    assert [s["id"] for s in view["surface_node"]] == ["t#2"]
    # The limit caps the slice.
    capped = ledger.scoped_view(object_types=["surface_node"], limit=2)
    assert len(capped["surface_node"]) == 2


def test_coverage_cells_are_stored_as_typed_objects(ledger: ResearchLedger) -> None:
    ledger.record_coverage_cell(
        CoverageCell(id="c1", surface="POST /x", risk_area="object authz", outcome="ruled_out")
    )
    cells = ledger.get_coverage_cells()
    assert [(c.id, c.outcome) for c in cells] == [("c1", "ruled_out")]


def test_notes_are_event_logged_and_deletion_is_itself_an_event(ledger: ResearchLedger) -> None:
    ledger.record_note(Note(id="n1", title="observation", content="saw a thing", agent_id="a1"))
    ledger.record_note(Note(id="n2", title="question", content="why?", agent_id="a2"))
    assert {n.id for n in ledger.get_notes()} == {"n1", "n2"}

    before = ledger.event_count()
    ledger.delete_note("n1")
    # The deleted note drops out of the live view, but the log only grew — the
    # deletion is an event, not an erasure.
    assert {n.id for n in ledger.get_notes()} == {"n2"}
    assert ledger.event_count() == before + 1


# ── the section-2.2 socket: evidence + verdict guards ────────────────────────


def test_a_finding_cannot_reference_evidence_that_was_never_recorded(
    ledger: ResearchLedger,
) -> None:
    with pytest.raises(DanglingEvidenceError) as excinfo:
        ledger.record_finding(Finding(id="f1", evidence_ids=["never-recorded"]))
    assert "never-recorded" in str(excinfo.value)


def test_confirmed_is_unreachable_without_a_passing_verdict(ledger: ResearchLedger) -> None:
    ledger.record_evidence(Evidence(id="e1", kind="proxy_exchange", evidence_refs=["101"]))
    ledger.record_finding(Finding(id="f1", evidence_ids=["e1"]))

    # A reach-only verdict (no oracle signal) cannot confirm.
    reach_only = ValidatorVerdict(
        id="v0", finding_id="f1", oracle="canary_read", passed=False, reach_only=True,
        author="validator-1",
    )
    with pytest.raises(VerdictError) as excinfo:
        ledger.confirm_finding("f1", reach_only)
    assert "reached" in str(excinfo.value)
    assert ledger.get_finding("f1").state == "open"  # unchanged

    # A passing verdict confirms, stamping the verdict id and author.
    ok = ValidatorVerdict(
        id="v1", finding_id="f1", oracle="canary_read", passed=True, author="validator-1",
        oracle_signal={"canary": "zc_planted"},
    )
    confirmed = ledger.confirm_finding("f1", ok)
    assert confirmed.state == "confirmed"
    assert confirmed.validator_verdict_id == "v1"
    assert confirmed.verdict_author == "validator-1"


def test_a_confirmed_finding_whose_verdict_was_never_recorded_is_rejected(
    ledger: ResearchLedger,
) -> None:
    """Recording a finding already in state 'confirmed' requires its verdict to
    exist and have passed — a confirmed state pointing at no recorded verdict is
    rejected, so 'confirmed' is reachable only through a real verdict."""
    with pytest.raises(VerdictError):
        ledger.record_finding(
            Finding(
                id="f1",
                state="confirmed",
                validator_verdict_id="phantom",
                verdict_author="someone",
            )
        )


def test_a_verdict_for_another_finding_cannot_confirm_this_one(ledger: ResearchLedger) -> None:
    ledger.record_finding(Finding(id="f1"))
    stray = ValidatorVerdict(
        id="v1", finding_id="other", oracle="effect_observed", passed=True, author="validator-1"
    )
    with pytest.raises(VerdictError):
        ledger.confirm_finding("f1", stray)
