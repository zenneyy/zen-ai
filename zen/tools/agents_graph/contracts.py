"""Typed delegation contracts for the multi-agent graph.

A parent spawning a hunter hands it a :class:`HuntTask`; the hunter hands back a
:class:`HuntReport` when it finishes. These are the structured halves of a
handoff that was previously carried entirely in a free-text task string — the
free text survives (as :attr:`HuntTask.rationale`, for the model's benefit), but
the contract the framework reasons over is typed.

Both models are **class-agnostic**: nothing here names, privileges, or assumes a
particular vulnerability class, technique, or target shape. The allowed
``vuln_class`` set is derived from the shipped ``vulnerabilities/*`` skill
catalog so it tracks the skills rather than a hand-maintained list.

Three axes describe a hunt, and they are orthogonal:

* ``basis`` is the *evidentiary grounding* of the driving hypothesis — whether
  it rests on something observed, on something the architecture implies, or on
  an unverified assumption. It is **not** a difficulty or sophistication level.
* ``depth_tier`` is *how far the prosecution goes* against the surface.
* ``impact_objective`` is *how far up the impact ladder* the hunt aims to reach.

Every ``depth_tier`` and every ``impact_objective`` rung admits the full
spectrum of research sophistication — from a first-pass confirmation through
original, previously-unseen technique. None of these enums, and none of the
examples in their field docs, cap the technical depth a hunter may bring.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zen.skills import get_vulnerability_class_names


if TYPE_CHECKING:
    from pydantic import ValidationInfo


# ``basis`` — evidentiary grounding of the hypothesis, NOT a difficulty tier.
HuntBasis = Literal["observed", "inferred_from_architecture", "assumed"]

# ``depth_tier`` — how far the prosecution of the hypothesis is expected to go.
DepthTier = Literal["confirm", "discover", "deep"]

# ``impact_objective`` / ``impact_reached`` — a rung on the impact ladder. The
# ladder orders *how far the consequence reaches*, not how hard the technique is:
# reach → trigger → primitive → weaponized → chained.
ImpactRung = Literal["reach", "trigger", "primitive", "weaponized", "chained"]

_SURFACE_CONTEXT_KEY = "known_surface_ids"


class HuntScope(BaseModel):
    """The boundary a hunter must stay inside.

    ``allow`` and ``deny`` are references in the run's own vocabulary (surface
    ids, host/path references, identifiers the parent already uses). They bound
    where the hunter may act; they say nothing about which techniques are
    permissible — technique selection is the hunter's discipline, within class.
    """

    model_config = ConfigDict(extra="forbid")

    allow: list[str] = Field(default_factory=list)
    """What the hunter may act against. Empty means "the assigned
    ``surface_refs`` and nothing wider" — not "anything"."""

    deny: list[str] = Field(default_factory=list)
    """Carve-outs the hunter must not touch even when they fall inside
    ``allow`` (out-of-engagement assets, fragile endpoints, a surface another
    agent owns)."""


class HuntBudget(BaseModel):
    """Soft ceilings on the effort a hunt should consume.

    Advisory, not a kill-switch: they tell the hunter when to stop widening and
    report what it has, so a deep prosecution does not run unbounded. A tight
    budget narrows breadth, never the depth of technique brought to the surface
    actually worked.
    """

    model_config = ConfigDict(extra="forbid")

    max_agent_turns: int | None = Field(default=None, ge=1)
    """Approximate agent-turn ceiling for the whole hunt."""

    max_target_interactions: int | None = Field(default=None, ge=1)
    """Approximate ceiling on interactions with the target (requests, probes,
    executions — whatever the class's medium is)."""

    wall_clock_seconds: int | None = Field(default=None, ge=1)
    """Approximate wall-clock ceiling."""

    notes: str = ""
    """Free-text budget guidance the model should weigh (e.g. "spend the
    budget on the identified primitive before any broad enumeration")."""


class RequiredEvidence(BaseModel):
    """The evidence schema a hunter owes back — what proof the report must carry.

    Defaults encode the validation discipline that applies to every class: a
    finding is not a finding without a working proof of concept, a negative
    control that fails when the mechanism is removed, and a stated resemblance
    boundary (what the finding is NOT). A parent raises or relaxes these per
    hunt.
    """

    model_config = ConfigDict(extra="forbid")

    proof_of_concept: bool = True
    """A captured, reproducible demonstration of the mechanism."""

    negative_control: bool = True
    """A control step that would fail if the finding were coincidence rather
    than the claimed mechanism."""

    resemblance_boundary: bool = True
    """An explicit statement of what the finding could be mistaken for and why
    it is not that."""

    captured_exchange_refs: bool = False
    """References to the captured interactions (whatever the class's medium is)
    that prove the finding, so the parent can replay them."""

    additional: list[str] = Field(default_factory=list)
    """Any further artifacts this specific hunt must return."""


class HuntTask(BaseModel):
    """A parent's structured delegation to a single hunter.

    Exactly one ``vuln_class`` per task — the structural half of the
    one-class-per-hunter rule. The free-text ``rationale`` carries the parent's
    reasoning for the model; the typed fields are the contract the framework
    enforces and the hunter reports against.
    """

    model_config = ConfigDict(extra="forbid")

    objective: str = Field(min_length=1)
    """What this hunt is for, in one or two sentences — the specific suspicion
    to prosecute against the assigned surface, phrased so the hunter knows what
    "done" looks like."""

    vuln_class: str = Field(min_length=1)
    """The single vulnerability class this hunter prosecutes, drawn from the
    shipped ``vulnerabilities/*`` catalog (e.g. a class slug such as ``xss`` or
    ``ssrf``; the allowed set is derived from the catalog, not hand-written).
    Exactly one — if a sink is a candidate for two classes, that is two hunts."""

    surface_refs: list[str] = Field(default_factory=list)
    """The surfaces to work, by the run's own surface ids. Each must resolve to
    a surface the run already knows about; a dangling reference is rejected so a
    hunt is never scoped to a surface nobody mapped."""

    hypothesis_ids: list[str] = Field(default_factory=list)
    """Ids of the threat-model hypotheses this hunt prosecutes, so its result
    can be reconciled back against the model that motivated it."""

    basis: HuntBasis
    """Evidentiary grounding of the driving hypothesis: ``observed`` (rests on a
    captured observation), ``inferred_from_architecture`` (implied by the
    documented structure, not yet seen), or ``assumed`` (a reasonable suspicion
    with no direct backing yet). This records *where the hypothesis stands as
    evidence* — it is not a difficulty rating and places no ceiling on the
    sophistication of the technique the hunter brings."""

    depth_tier: DepthTier
    """How far the prosecution goes. ``confirm`` — settle a specific, already
    well-formed suspicion against the surface. ``discover`` — work the class's
    variant tree across the surface to find what is there. ``deep`` — exhaust
    the class's full technique space, including bypass families for any control
    encountered and multi-step and engine-/parser-differential variants. Each
    tier spans beginner-through-expert technique; ``deep`` is broader in scope,
    not merely "harder"."""

    impact_objective: ImpactRung
    """How far up the impact ladder the hunt aims to carry a confirmed finding:
    ``reach`` (show the surface is attacker-reachable) → ``trigger`` (make the
    mechanism fire) → ``primitive`` (establish a reusable capability) →
    ``weaponized`` (turn the primitive into a concrete, demonstrated impact) →
    ``chained`` (compose it with other primitives for end-to-end impact). The
    ladder orders consequence, not technical difficulty — reaching any rung may
    demand anything from a textbook step to original research."""

    prior_art: list[str] = Field(default_factory=list)
    """References the hunter should build on rather than rediscover — prior
    findings, notes, advisories, or known technique families relevant to this
    surface and class."""

    methodology_refs: list[str] = Field(default_factory=list)
    """Skill or methodology references the hunter should load and apply (e.g.
    the class's own ``vulnerabilities/*`` skill or a ``tooling/*`` playbook).
    Guidance, not a cap: the hunter loads whatever the hunt needs."""

    root_cause_required: bool = False
    """When true, a confirmed finding must be traced to its root cause (not only
    demonstrated), because the parent intends to reason about or remediate the
    underlying defect."""

    variant_directive: str = ""
    """Which variant families to prioritize or expand first, when the class's
    technique space is large and the parent has a view on where to start."""

    scope: HuntScope
    """The boundary the hunter must stay inside. Required — a hunt without a
    stated scope is never dispatched."""

    budget: HuntBudget | None = None
    """Soft effort ceilings, if any. ``None`` means the run's standing defaults
    apply."""

    required_outputs: RequiredEvidence = Field(default_factory=RequiredEvidence)
    """The evidence schema the resulting :class:`HuntReport` must satisfy."""

    stop_conditions: list[str] = Field(default_factory=list)
    """Explicit conditions under which the hunter should stop and report —
    beyond exhausting the variant tree (e.g. "stop once the primitive is
    established; the parent will scope the chain separately")."""

    parent_context_digest: str = ""
    """What the parent already knows and the hunter should not re-derive — the
    relevant slice of recon, the threat-model state, what adjacent hunters have
    covered. Keeps the hunter from repeating mapping that is already done."""

    rationale: str = ""
    """Free-text reasoning from the parent for the model's benefit. This is
    context, not contract: the typed fields above are what the framework
    enforces."""

    @field_validator("vuln_class")
    @classmethod
    def _one_known_class(cls, value: str) -> str:
        value = value.strip()
        allowed = get_vulnerability_class_names()
        # When the catalog cannot be read (e.g. a stripped-down environment),
        # do not reject every class — membership simply cannot be verified.
        if allowed and value not in allowed:
            raise ValueError(
                f"vuln_class {value!r} is not a known vulnerability class. "
                f"Pass exactly one class from the vulnerabilities/* catalog: "
                f"{sorted(allowed)}"
            )
        return value

    @model_validator(mode="after")
    def _surface_refs_resolve(self, info: ValidationInfo) -> HuntTask:
        """Every ``surface_ref`` must resolve to a surface the run knows about.

        The known-surface set is supplied through validation context
        (``context={"known_surface_ids": {...}}``) by the spawn path, which
        reads it from live run state. When no set is supplied the check is
        skipped — membership cannot be resolved without it, and an unresolved
        context is not grounds to reject an otherwise well-formed task.
        """
        known = None
        if info.context:
            known = info.context.get(_SURFACE_CONTEXT_KEY)
        if known is None:
            return self
        known_set = set(known)
        unknown = [ref for ref in self.surface_refs if ref not in known_set]
        if unknown:
            raise ValueError(
                f"surface_ref(s) do not resolve to a known surface id: {sorted(unknown)}. "
                f"Known surface ids: {sorted(known_set)}"
            )
        return self

    def render_block(self) -> str:
        """Render the task as a structured, plain-text delegation block.

        Plain text (not XML/JSON) to match the completion-report style — no
        escaping concerns, nothing for a downstream parser to choke on. The
        ``rationale`` is included as the parent's reasoning, clearly marked as
        context rather than contract.
        """
        lines: list[str] = [
            "== Hunt Task (structured delegation contract) ==",
            f"Objective: {self.objective}",
            f"Vulnerability class (exactly one): {self.vuln_class}",
            f"Hypothesis basis (evidentiary grounding, not difficulty): {self.basis}",
            f"Depth tier: {self.depth_tier}",
            f"Impact objective (ladder rung to reach): {self.impact_objective}",
            f"Surfaces: {', '.join(self.surface_refs) or '(none specified)'}",
            f"Scope allow: {', '.join(self.scope.allow) or '(the surfaces above)'}",
            f"Scope deny: {', '.join(self.scope.deny) or '(none)'}",
        ]
        if self.hypothesis_ids:
            lines.append(f"Threat-model hypothesis ids: {', '.join(self.hypothesis_ids)}")
        if self.variant_directive:
            lines.append(f"Variant directive: {self.variant_directive}")
        if self.prior_art:
            lines.append(f"Prior art to build on: {', '.join(self.prior_art)}")
        if self.methodology_refs:
            lines.append(f"Methodology refs to apply: {', '.join(self.methodology_refs)}")
        lines.append(f"Root cause required for a confirmed finding: {self.root_cause_required}")
        req = self.required_outputs
        required = [
            label
            for label, on in (
                ("proof_of_concept", req.proof_of_concept),
                ("negative_control", req.negative_control),
                ("resemblance_boundary", req.resemblance_boundary),
                ("captured_exchange_refs", req.captured_exchange_refs),
            )
            if on
        ]
        required.extend(req.additional)
        lines.append(f"Required evidence: {', '.join(required) or '(none)'}")
        if self.budget is not None:
            budget_bits = [
                f"{name}={value}"
                for name, value in (
                    ("max_agent_turns", self.budget.max_agent_turns),
                    ("max_target_interactions", self.budget.max_target_interactions),
                    ("wall_clock_seconds", self.budget.wall_clock_seconds),
                )
                if value is not None
            ]
            if self.budget.notes:
                budget_bits.append(f"notes={self.budget.notes}")
            if budget_bits:
                lines.append(f"Budget (soft): {', '.join(budget_bits)}")
        if self.stop_conditions:
            lines.append(f"Stop conditions: {'; '.join(self.stop_conditions)}")
        if self.parent_context_digest:
            lines.append(f"Parent context (do not re-derive): {self.parent_context_digest}")
        if self.rationale:
            lines.append("")
            lines.append(f"Parent rationale (context, not contract): {self.rationale}")
        lines.append("== End hunt task ==")
        return "\n".join(lines)


class HuntReport(BaseModel):
    """A hunter's structured result, handed back at ``agent_finish``.

    The parent reads the :meth:`digest` of this from its inbox instead of
    re-reading shared state. A confirmed finding (any ``filed_report_ids``)
    obliges a stated ``root_cause`` — a finding filed without naming why the
    defect exists is incomplete.
    """

    model_config = ConfigDict(extra="forbid")

    hypotheses_tested: list[str] = Field(default_factory=list)
    """Which hypotheses this hunt actually prosecuted (ids or short labels),
    so the parent can reconcile intended against tested."""

    evidence_ids: list[str] = Field(default_factory=list)
    """References to the captured evidence backing the result — whatever the
    class's medium is (captured exchanges, execution traces, artifacts)."""

    coverage_deltas: list[str] = Field(default_factory=list)
    """Coverage entries this hunt created or moved, so the parent's
    reconciliation sees what the ledger now reflects."""

    new_surface: list[str] = Field(default_factory=list)
    """Surfaces discovered during the hunt that were not in the task — leads
    the parent may scope as new work."""

    root_cause: str = ""
    """Why the defect exists, at its source. Required (non-empty) whenever a
    finding was confirmed and filed; optional otherwise."""

    impact_reached: ImpactRung | None = None
    """The highest impact-ladder rung this hunt actually demonstrated (not what
    was hoped for). ``None`` when nothing was confirmed."""

    variant_leads: list[str] = Field(default_factory=list)
    """Untried or partially-tried variant families worth a follow-up hunt — the
    child hypotheses this hunt surfaced but did not prosecute."""

    filed_report_ids: list[str] = Field(default_factory=list)
    """Ids of vulnerability reports this hunt filed. Non-empty means a finding
    was confirmed, which obliges ``root_cause``."""

    open_items: list[str] = Field(default_factory=list)
    """Candidates the hunt could neither confirm nor rule out, and anything it
    ran out of budget or access to finish — handed up rather than dropped."""

    @model_validator(mode="after")
    def _confirmed_finding_has_root_cause(self) -> HuntReport:
        if self.filed_report_ids and not self.root_cause.strip():
            raise ValueError(
                "root_cause is required when a finding is confirmed "
                f"(filed_report_ids={self.filed_report_ids}); a filed finding without a "
                "stated root cause is incomplete."
            )
        return self

    def digest(self) -> dict[str, Any]:
        """The compact view the parent reads from its inbox.

        Carries, at minimum, the impact rung reached and the variant leads, so
        the parent can prioritize follow-up work without re-reading the full
        report from shared state.
        """
        return {
            "impact_reached": self.impact_reached,
            "variant_leads": list(self.variant_leads),
            "filed_report_ids": list(self.filed_report_ids),
            "open_items": list(self.open_items),
            "new_surface": list(self.new_surface),
        }
