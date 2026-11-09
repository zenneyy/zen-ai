"""The typed objects an :class:`~zen.tools.ledger.store.ResearchLedger` holds.

These are the *structured* substance of a run's research state — the five record
kinds the ledger stores as an append-only, provenance-bearing log, plus the
verdict record that section 2.2 produces. Everything here is **class-agnostic**:
the objects describe *surfaces, suspicions, captured evidence, reviewed space,
candidates, and verdicts* in general terms. None of them names, privileges, or
assumes a particular vulnerability class, technique, or target shape.

Two of the five record kinds already exist as validated models and are reused
verbatim rather than re-declared, so there is one definition of each:

* :class:`~zen.tools.threat_model.schema.Hypothesis` — a suspected weakness with
  its evidentiary ``basis`` and lifecycle ``state``;
* :class:`~zen.tools.threat_model.schema.Finding` — a hunter's candidate, which
  is unreachable in ``state == "confirmed"`` without a validator verdict.

The three declared here deepen the structured-state work beyond the transitional
block 1.3 seeded:

* :class:`SurfaceNode` — a reachable point in the system described by structure
  (reachability, trust context, component fingerprint, what the caller controls,
  enumeration depth), not by any class it might be vulnerable to;
* :class:`Evidence` — a captured observation carrying its provenance (the
  tool-call ids that produced it, hashes of the raw output, the authoring agent
  and task) **and a re-executable descriptor**, so a finding's support can be
  replayed by non-model code rather than trusted as a quoted string. This is the
  hook section 2.2's validators replay;
* :class:`CoverageCell` — one surface-times-risk cell of the coverage ledger.

And :class:`ValidatorVerdict` is the record a deterministic validator or a
clean-context reviewer writes: the *only* thing that may carry a finding to
``confirmed``. It records the oracle by its observable shape, whether the verdict
passed, who authored it, and — load-bearing for the Target-B lesson — whether
the replayed evidence proved only that a surface was *reached* or that the
exploit was actually *performed and its effect observed*.

As with ``basis`` elsewhere in the engine, nothing here is a difficulty tier.
Every field records *what is structurally true* — how reachable, how grounded,
how far demonstrated — never how hard the technique was.
"""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

# Reused verbatim so there is exactly one definition of each. These are the two
# record kinds 1.3 already validated; the ledger stores them unchanged.
from zen.tools.threat_model.schema import Finding, Hypothesis


__all__ = [
    "CoverageCell",
    "Evidence",
    "EvidenceReplay",
    "Finding",
    "Hypothesis",
    "Note",
    "Reachability",
    "SurfaceNode",
    "TrustInputModel",
    "ValidatorVerdict",
    "evidence_hash",
    "utc_now",
]


def utc_now() -> str:
    """One timestamp spelling, so every record is stamped the same way."""
    return datetime.now(UTC).isoformat()


def evidence_hash(raw: str | bytes) -> str:
    """Hash a captured raw output so its integrity is verifiable later.

    The hash is stored on :class:`Evidence` as provenance: a validator that
    re-executes the evidence can confirm it is replaying the same captured output
    the hunter recorded, not a different one substituted since. Class-agnostic —
    it hashes bytes, and knows nothing about what they contain.
    """
    data = raw.encode("utf-8") if isinstance(raw, str) else raw
    return hashlib.sha256(data).hexdigest()


# ── SurfaceNode ──────────────────────────────────────────────────────────────

Reachability = Literal["publicly_reachable", "reached_through_component", "unknown"]
"""How a surface is reached:

* ``publicly_reachable`` — an attacker can reach it directly from outside;
* ``reached_through_component`` — it is reachable only *through* another
  component's behavior (a server-side request, an internal link, a forwarded
  identity), so it is not on the public edge;
* ``unknown`` — not yet established.

This is reachability, not exploitability: a publicly-reachable surface may be
perfectly safe, and a deeply-internal one may be the crown jewels."""

TrustInputModel = Literal["path", "body", "header", "param", "none", "mixed", "unknown"]
"""What the caller controls at a surface — the shape of attacker influence:
which part of the request (``path`` / ``body`` / ``header`` / ``param``), a
``mix`` of them, ``none`` (the caller influences nothing here), or ``unknown``.
Class-agnostic: it describes the input channel, not what could be done through
it."""


class SurfaceNode(BaseModel):
    """A reachable point in the system, described by structure alone.

    A surface node says *where* something is in the system and *what an actor
    controls when they reach it* — never what class of weakness it might hold.
    It is the typed form of a processing-stage hop (and, in time, of any mapped
    endpoint): the structured ground truth the architecture-implied-classes gate
    and section 2.2's validators reason over, instead of re-parsing recon prose.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle for this surface within the run — the target of a
    hypothesis's or hunt's ``surface_refs``, and named in gate rejections."""

    source_identity: str = ""
    """The normalized target identity this surface belongs to, so the ledger can
    group a target's surfaces (the architecture gate reasons per target)."""

    taxonomy: str = "component_hop"
    """What kind of surface this is in general terms — ``component_hop`` (a
    processing stage in the request path), ``endpoint``, ``parameter``,
    ``file``, and so on. A neutral structural label, never a vulnerability
    class."""

    name: str = ""
    """The surface's label as recon wrote it (a component name, a route). Kept
    raw so the architecture-implied-classes mapping sees exactly the text it saw
    before the ledger existed — the behavior-equivalence bridge."""

    role: str = ""
    """What function this surface serves, as recon wrote it. Raw, for the same
    behavior-equivalence reason as ``name``."""

    kind: str = ""
    """The *typed* structural kind inferred from ``name``/``role`` — e.g.
    ``transforming_intermediary``, ``application_handler``,
    ``authz_decision_point``. This is the 2.1 seam the memory flagged: a typed
    kind the implied-classes mapping can consume instead of keyword-sniffing free
    text. Empty when no kind was recognised; advisory, never a cap."""

    reachability: Reachability = "unknown"
    """How the surface is reached (see :data:`Reachability`)."""

    trust_context: str = ""
    """The authority / trust boundary this surface sits behind, in words — e.g.
    ``edge-facing``, ``behind <component>``, ``internal, trusts forwarded
    identity``. What an attacker must already have crossed to be here."""

    component_fingerprint: str = ""
    """The framework / parser / client identity observed at this surface, if any
    (e.g. a server banner, a template engine, an HTTP client). Empty when not
    fingerprinted."""

    input_model: TrustInputModel = "unknown"
    """What the caller controls here (see :data:`TrustInputModel`)."""

    observed_behaviors: list[str] = Field(default_factory=list)
    """Behaviors actually observed at this surface — redirects followed, headers
    rewritten, errors disclosed — in neutral terms. Evidence of how it acts, not
    a claim about what it is vulnerable to."""

    enumerated: bool = False
    """Whether a content/route discovery pass has been run against this surface.
    The indirect-service enumeration gate reads this instead of parsing prose."""

    enumeration_depth: int = Field(default=0, ge=0)
    """How deeply this surface has been enumerated — 0 (not enumerated) upward.
    A coarse measure of how much of the surface's own space has been mapped."""

    order_index: int = Field(default=0, ge=0)
    """This surface's position in the request path (0 = front-most entry point),
    so adjacent surfaces can be paired for the boundary-kind reasoning the
    architecture gate does."""

    linked_hypothesis_ids: list[str] = Field(default_factory=list)
    """Ids of hypotheses that prosecute this surface, so a surface and the
    suspicions about it stay linked."""

    def as_hop(self) -> dict[str, str]:
        """Render back to the ``{name, role}`` hop shape the architecture mapping
        consumes, so the gate's reasoning is byte-identical to the pre-ledger
        path that read the raw architecture store."""
        hop = {"name": self.name}
        if self.role:
            hop["role"] = self.role
        return hop


# ── Evidence ─────────────────────────────────────────────────────────────────


class EvidenceReplay(BaseModel):
    """A re-executable descriptor of how a piece of evidence was obtained.

    This is what makes evidence *re-checkable* rather than a quoted string: the
    exact inputs a validator replays in non-model code to observe the effect for
    itself. Class-agnostic — it names a medium and carries opaque inputs; it does
    not model any specific exploit.
    """

    model_config = ConfigDict(extra="forbid")

    medium: str = ""
    """The medium to replay through — ``http`` (an exchange), ``command`` (a
    subprocess), ``browser`` (a scripted interaction), or any other the engine
    grows. Opaque to the ledger; the replayer dispatches on it."""

    inputs: dict[str, str] = Field(default_factory=dict)
    """The exact, opaque inputs to replay — for ``http`` a method/url/headers/
    body; for ``command`` an argv and stdin; for ``browser`` a scripted step.
    Stored as strings so the record is serialisable and the ledger never has to
    understand the class-specific meaning."""

    negative_control: dict[str, str] = Field(default_factory=dict)
    """The paired negative-control inputs, when the oracle is differential — the
    A/B control a validator replays alongside ``inputs`` to require the predicted
    differential. Empty when the oracle does not need one."""


class Evidence(BaseModel):
    """A captured observation, carrying its provenance and a way to replay it.

    Evidence is the ledger's provenance-bearing unit. Every piece records *who*
    produced it (agent and task), *through which tool calls*, *hashed proof* of
    the raw output so a replay can confirm it is the same bytes, the opaque
    references the run uses to address it (e.g. proxy request ids), **and the
    re-executable descriptor** a validator replays. A finding may cite only
    evidence that was actually recorded here — the ledger rejects a dangling
    reference — so a confirmed finding's support is always re-checkable, never a
    free-floating quote.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle for this evidence within the run — what a
    :class:`~zen.tools.threat_model.schema.Finding` cites in
    ``evidence_ids`` and what a verdict records as replayed."""

    kind: str = ""
    """What kind of observation this is, in neutral terms — ``proxy_exchange``,
    ``command_exec``, ``browser_capture``, ``artifact``. The medium, not a
    class."""

    tool_call_ids: list[str] = Field(default_factory=list)
    """Ids of the tool calls that produced this evidence — the provenance trail
    from the captured observation back to the action that captured it."""

    raw_output_hashes: list[str] = Field(default_factory=list)
    """Hashes (see :func:`evidence_hash`) of the raw captured output(s). A
    replay confirms it is operating on the same bytes the hunter recorded, so
    the evidence cannot be quietly swapped between capture and validation."""

    evidence_refs: list[str] = Field(default_factory=list)
    """The run's own opaque references to this evidence — proxy request ids, log
    offsets, artifact paths. What a reader follows to the raw capture."""

    agent_id: str = ""
    """Id of the agent that captured this evidence."""

    task_id: str = ""
    """Id of the hunt task this evidence was captured under, if any."""

    replay: EvidenceReplay = Field(default_factory=EvidenceReplay)
    """The re-executable descriptor (see :class:`EvidenceReplay`). The hook a
    validator replays to observe the effect in non-model code."""

    summary: str = ""
    """A short human-readable note on what the evidence shows. Context for the
    reader; the typed fields above are what a validator reads."""

    created_at: str = Field(default_factory=utc_now)
    """When the evidence was recorded."""


# ── CoverageCell ─────────────────────────────────────────────────────────────


class CoverageCell(BaseModel):
    """One surface-times-risk cell of the coverage ledger, as a typed object.

    Coverage answers *what was looked at and how it closed* — the negative space
    a report needs. The cell is the typed form of a coverage entry; it mirrors
    the shape the coverage tool already records, so the two cannot drift.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle — the coverage entry id."""

    surface: str = ""
    """What was reviewed — an endpoint, route, parameter, file, component."""

    risk_area: str = ""
    """What it was reviewed *for*, in the run's own words."""

    outcome: str = ""
    """How the review closed — one of the coverage tool's outcomes
    (``reported`` / ``no_issue_found`` / ``ruled_out`` / ``not_applicable`` /
    ``needs_follow_up``)."""

    evidence: str = ""
    """How the reviewer knows — the control, the test, or the gap."""

    approaches_tried: list[str] = Field(default_factory=list)
    """The discrete approaches exercised against this surface."""

    agent_id: str = ""
    """Id of the agent that recorded the cell."""

    agent_name: str = ""
    """Name of the agent that recorded the cell."""

    created_at: str = Field(default_factory=utc_now)
    """When the cell was first recorded."""


# ── Note (free-text agent scratch, event-logged for resume) ──────────────────


class Note(BaseModel):
    """A free-text note an agent wrote, carried on the ledger for resume.

    Notes are not a typed *research* object the gates or validators reason over —
    they are an agent's own scratch (an observation, a methodology step, an open
    question). They live on the ledger so a resumed run replays them like every
    other event, with the note store's dict kept as the live read-model.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    title: str = ""
    content: str = ""
    category: str = "general"
    tags: list[str] = Field(default_factory=list)
    agent_id: str = ""
    agent_name: str = ""
    created_at: str = ""
    updated_at: str = ""


# ── ValidatorVerdict (the section-2.2 record) ────────────────────────────────

OracleShape = Literal[
    "canary_read",
    "effect_observed",
    "differential",
    "crash_signature",
    "reviewer_differential",
]
"""The observable a verdict rests on, by its *shape*, never by naming a class
exploit:

* ``canary_read`` — a planted, per-run, high-entropy canary appeared in the
  replayed response (the protected read actually occurred);
* ``effect_observed`` — a server-observable state change or out-of-band
  interaction the validator read back after re-executing;
* ``differential`` — the predicted difference between the exploit input and a
  negative control held on re-execution;
* ``crash_signature`` — a crash / sanitizer signature appeared on re-execution;
* ``reviewer_differential`` — a clean-context reviewer re-observed a
  role-/tenant-/state-differential behavior itself (for classes with no
  mechanical oracle).

Each is defined by what the validator *observes on re-execution*, so it can tell
"reached the surface" from "performed the exploit and saw its effect"."""


class ValidatorVerdict(BaseModel):
    """A deterministic validator's or a reviewer's verdict on a finding.

    This is the only record that may carry a finding to ``confirmed``. It exists
    so that "confirmed" means *validated outside the model*: a re-executable
    replay of the finding's own evidence that observed the oracle signal — not a
    trace or signature match, which cannot tell "reached the tier" from
    "performed the intended exploit and observed its effect."
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle — what a :class:`~zen.tools.threat_model.schema.Finding`
    names in ``validator_verdict_id`` to reach ``confirmed``."""

    finding_id: str = ""
    """Id of the finding this verdict is about."""

    oracle: OracleShape
    """The observable shape this verdict rests on (see :data:`OracleShape`)."""

    passed: bool
    """Whether the oracle signal was observed on re-execution. ``True`` is the
    only value that confirms a finding; ``False`` records a rejection with its
    reason, which is kept so a false candidate's rejection is auditable."""

    reach_only: bool = False
    """Load-bearing for the Target-B lesson: ``True`` when the replayed evidence
    proved only that a surface/tier was *reached* and produced **no** oracle
    signal — the exploit was not performed, so the verdict does not pass. The
    field makes the distinction explicit rather than implicit in ``passed``."""

    author: str = Field(min_length=1)
    """Id of the validator or reviewer that authored the verdict — a
    confirmation is attributable or it is not a confirmation."""

    oracle_signal: dict[str, str] = Field(default_factory=dict)
    """The captured oracle signal — the matched canary, the read-back effect
    token, the observed differential, or the crash signature. Present and
    non-empty on a pass; empty on a reach-only rejection. This is the re-observed
    proof the verdict carries alongside the re-executable inputs."""

    replayed_evidence_ids: list[str] = Field(default_factory=list)
    """Ids of the :class:`Evidence` the validator re-executed to reach this
    verdict — the exact, recorded support it replayed."""

    detail: str = ""
    """A short statement of how the verdict was reached — which oracle, what was
    observed or not observed. For the reader; the typed fields are the contract."""

    created_at: str = Field(default_factory=utc_now)
    """When the verdict was authored."""
