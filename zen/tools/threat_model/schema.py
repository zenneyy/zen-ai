"""Structured Hypothesis / Finding records carried in the threat-model markdown.

The threat model stays a markdown document (the event-sourced ledger is a later
section). These models are the *structured* half of it: a transitional block
parsed out of the markdown's **Hypotheses** section so the save gate and the
generated persona CONTRACT reason over the same typed shape instead of over
prose.

Three things live here and are imported by every consumer so they cannot drift:

* :class:`Hypothesis` and :class:`Finding` — the validated records.
* The **in-markdown hypothesis convention** (:data:`HYPOTHESIS_CONVENTION`, plus
  the ``HYPOTHESIS_*`` tokens) — the single, greppable grammar one hypothesis is
  written in, and the parser (:func:`parse_hypotheses`) that reads it.
* :data:`HYPOTHESES_SECTION_ALIASES` — the headings that name the section,
  shared with the threat-model tool's required-section table.

``basis`` is reused verbatim from the delegation contracts
(:data:`zen.tools.agents_graph.contracts.HuntBasis`), and so are the depth and
impact ladders (:data:`DepthTier`, :data:`ImpactRung`). There is one definition
of each; nothing here re-declares them.

A word the field docs keep making, because it is the load-bearing distinction:
``basis`` is *evidentiary grounding* — how well a claim is supported — and
nothing else. It is **not** a difficulty rating, a sophistication tier, or a
measure of how hard the technique is. Where a hypothesis sits on the ambition
scale lives in ``target_depth`` and ``impact_objective``. Every ``basis`` value
and every rung of those ladders admits the full spectrum of research, from a
first-pass confirmation to original, previously-unseen technique; none of them
caps the depth a researcher may bring.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal, get_args

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from zen.skills import get_vulnerability_class_names
from zen.tools.agents_graph.contracts import DepthTier, HuntBasis, ImpactRung


if TYPE_CHECKING:
    from collections.abc import Sequence

    from pydantic import ValidationInfo


# ── the in-markdown hypothesis convention (single source of truth) ───────────
#
# One hypothesis is ONE Markdown list item on ONE line. Its fields are written
# as ``key: value`` pairs separated by ``" | "`` (space-pipe-space); a list
# value (evidence ids, dependency ids) is comma-separated and an
# ``inference_chain`` is semicolon-separated. ``id`` and ``basis`` are required
# on every entry; the rest are optional. A value must not itself contain the
# ``" | "`` field separator.
#
# Both the save-gate parser (threat_model.tools._save_impl) and the generated
# persona CONTRACT (zen.agents.contract) import these constants, so the grammar
# they enforce and the grammar they teach are the same bytes.

HYPOTHESIS_BULLETS: tuple[str, ...] = ("- ", "* ")
"""A hypothesis entry is a Markdown list item beginning with one of these."""

HYPOTHESIS_FIELD_SEP = " | "
"""Fields within one entry are separated by space-pipe-space."""

HYPOTHESIS_KV_SEP = ":"
"""Each field is ``key: value`` (split on the first colon only)."""

HYPOTHESIS_ID_LIST_SEP = ","
"""Items within an id-list field (evidence ids, ``depends_on``) are comma-separated."""

HYPOTHESIS_CHAIN_SEP = ";"
"""Steps within ``inference_chain`` are semicolon-separated."""

BASIS_MARKER = "basis"
"""The explicit, greppable key every hypothesis must carry."""

HYPOTHESES_SECTION_ALIASES: tuple[str, ...] = (
    "hypotheses",
    "attacker hypotheses",
    "hypothesized vulnerabilities",
)
"""Headings that name the Hypotheses section. Shared with the tool's
required-section table so the two cannot disagree on where hypotheses live."""

# A ready-to-read example used verbatim by the generated CONTRACT, so the
# grammar an agent is shown is the grammar the gate parses. Class-agnostic: the
# mechanism and observable are placeholders, not a specific vulnerability.
HYPOTHESIS_EXAMPLE = (
    "- id: H1 | basis: observed | mechanism: <how the weakness would work> | "
    "predicted_observable: <the signal that would confirm it> | "
    "supporting_evidence_ids: <evidence-id>, <evidence-id> | "
    "target_depth: discover | impact_objective: primitive | "
    "rationale: <free-text reasoning>"
)


@dataclass(frozen=True)
class _HypothesisConventionSpec:
    """The convention as importable data, so consumers describe one grammar."""

    bullets: tuple[str, ...]
    field_sep: str
    kv_sep: str
    id_list_sep: str
    chain_sep: str
    basis_marker: str
    section_aliases: tuple[str, ...]
    example: str

    def describe(self) -> list[str]:
        """Human-readable lines describing the grammar (rendered into CONTRACT)."""
        return [
            "Each hypothesis is one Markdown list item on one line, in the "
            "Hypotheses section, written as `key: value` fields separated by "
            "` | ` (space-pipe-space).",
            f"`{self.basis_marker}:` is required on every hypothesis and must be "
            f"one of {', '.join(HYPOTHESIS_BASIS_VALUES)} — this is the evidentiary "
            "grounding of the claim, not a difficulty or depth rating.",
            "`basis: observed` requires a non-empty `supporting_evidence_ids` "
            "(ids of recorded tool-call evidence); `basis: "
            "inferred_from_architecture` requires a non-empty `inference_chain` "
            "(the architecture-to-hypothesis reasoning steps, `;`-separated).",
            "Depth and ambition live in `target_depth` and `impact_objective`, "
            "not in `basis`; every basis value admits the full spectrum of "
            "research depth.",
            f"Example — {self.example}",
        ]


HYPOTHESIS_CONVENTION = _HypothesisConventionSpec(
    bullets=HYPOTHESIS_BULLETS,
    field_sep=HYPOTHESIS_FIELD_SEP,
    kv_sep=HYPOTHESIS_KV_SEP,
    id_list_sep=HYPOTHESIS_ID_LIST_SEP,
    chain_sep=HYPOTHESIS_CHAIN_SEP,
    basis_marker=BASIS_MARKER,
    section_aliases=HYPOTHESES_SECTION_ALIASES,
    example=HYPOTHESIS_EXAMPLE,
)

# The basis values, surfaced as a tuple for the CONTRACT and alignment test.
HYPOTHESIS_BASIS_VALUES: tuple[str, ...] = ("observed", "inferred_from_architecture", "assumed")


# ── hypothesis disposition (how an open/blocked lead is handled at closure) ───
#
# A hypothesis left ``open`` or ``blocked`` at scan close is not dropped in
# silence — it carries an explicit *disposition* recording how the lead was
# handled. This is the low-friction, INLINE channel: a ``disposition:`` field
# written straight onto the hypothesis line, which is what an agent reaches for
# first. It sits alongside the dedicated ``## Deferred Hypotheses`` section
# further down; both record the same thing and both satisfy the finish-time
# closure gate. The values live here once, so the :class:`Hypothesis` validator,
# the closure gate in ``finish_scan``, and the generated persona CONTRACT read a
# single definition and cannot drift.
#
# The values are generic and class-agnostic: they describe *how a lead was
# handled*, never a vulnerability class and never a difficulty.

HypothesisDisposition = Literal["deferred", "accepted_risk", "out_of_scope", "resolved_elsewhere"]
"""How an open/blocked hypothesis was handled at closure:

* ``deferred`` — carried forward for later work (needs access, time, or a
  precondition not met this engagement);
* ``accepted_risk`` — acknowledged and accepted without further prosecution;
* ``out_of_scope`` — judged to lie outside this engagement's scope;
* ``resolved_elsewhere`` — handled by another hypothesis, finding, or report.

A ``confirmed`` / ``refuted`` hypothesis is already terminal and needs none."""

HYPOTHESIS_DISPOSITION_VALUES: tuple[str, ...] = get_args(HypothesisDisposition)
"""The disposition values as a tuple — surfaced for the CONTRACT, the closure-gate
message, and the alignment test. Derived from the Literal so there is one source."""

DISPOSITION_LINE_EXAMPLE = (
    "- id: <id> | basis: <basis> | ... | state: blocked | disposition: deferred | "
    "disposition_reason: <why this open/blocked lead is carried forward rather than resolved now>"
)
"""The inline-disposition grammar, shown verbatim in the generated CONTRACT and the
closure-gate rejection so the grammar taught is the grammar the gate reads."""

DISPOSITION_CONVENTION = (
    "A hypothesis left `state: open` or `state: blocked` at scan close records how the lead "
    "was handled with an inline `disposition:` field on its own hypothesis line — one of "
    f"{', '.join(HYPOTHESIS_DISPOSITION_VALUES)} (optionally a free-text `disposition_reason:`). "
    "A `confirmed` or `refuted` hypothesis is already terminal and needs none; a dedicated "
    "`## Deferred Hypotheses` record carries the same disposition where that reads more naturally."
)
"""One class-agnostic statement of the disposition rule, consumed by the closure-gate
rejection and the generated CONTRACT so the teaching and the enforcement are one source."""


# ── evidence-id shape ────────────────────────────────────────────────────────
#
# What counts as a *resolvable* evidence id given the current engine: a proxy
# (Caido) request id — numeric, verifiable against the live project via
# ``zen.tools.proxy.tools.existing_request_ids``. The command log records
# command *strings*, not addressable ids, so it offers nothing to reference by
# id. Shape validation below stays deliberately general (any bounded,
# whitespace-free token) so a future evidence namespace is not excluded;
# membership is resolved separately, and only when a known-evidence set is
# supplied (see :meth:`Hypothesis._check_grounding`).

_EVIDENCE_ID_MAX_CHARS = 64


def _validate_evidence_ids(values: list[str]) -> list[str]:
    cleaned: list[str] = []
    for raw in values:
        token = raw.strip()
        if not token:
            raise ValueError("an evidence id cannot be empty")
        if len(token) > _EVIDENCE_ID_MAX_CHARS:
            raise ValueError(f"evidence id {token!r} exceeds {_EVIDENCE_ID_MAX_CHARS} characters")
        if any(ch.isspace() for ch in token) or HYPOTHESIS_FIELD_SEP.strip() in token:
            raise ValueError(f"evidence id {token!r} must be a single whitespace-free token")
        cleaned.append(token)
    return cleaned


HypothesisState = Literal["open", "testing", "confirmed", "refuted", "blocked"]
FindingState = Literal["open", "testing", "confirmed", "refuted", "blocked"]
Confidence = Literal["low", "medium", "high"]


class Hypothesis(BaseModel):
    """A single suspected weakness, with its evidentiary grounding made explicit.

    A hypothesis records *what might be wrong and how well the suspicion is
    supported* — never how hard it would be to prosecute. The sophistication a
    researcher brings is unbounded at every grounding and every depth: an
    ``assumed`` hypothesis at ``target_depth: confirm`` may still demand
    original technique, and an ``observed`` one may fall to a textbook step.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle for this hypothesis within the model — named in gate
    rejections, and the target of another hypothesis's ``depends_on`` /
    ``variant_of``."""

    basis: HuntBasis
    """Evidentiary grounding, and nothing else. ``observed`` — rests on a
    captured observation (which ``supporting_evidence_ids`` must cite);
    ``inferred_from_architecture`` — implied by the documented structure, not
    yet seen (which ``inference_chain`` must lay out); ``assumed`` — a
    reasonable suspicion with no direct backing yet. This is *how well-supported
    the claim is*, NOT a difficulty tier and NOT a depth tier; it places no
    ceiling on the technique the hunt may require."""

    vuln_class: str = ""
    """The vulnerability class this hypothesis prosecutes, drawn from the shipped
    ``vulnerabilities/*`` catalog (e.g. ``idor``, ``ssrf``). Optional in general,
    but it is how a hypothesis *names* the class it covers, so the
    architecture-implied-classes completeness gate can tell which implied classes
    the model has addressed. Independent of ``basis``: an architecture-implied
    class is typically carried as a ``basis: inferred_from_architecture``
    hypothesis with its ``vuln_class`` set, but any basis may name a class."""

    mechanism: str = ""
    """How the weakness would work — the causal story from attacker-controlled
    input to the consequence, at whatever depth the claim warrants."""

    predicted_observable: str = ""
    """The specific signal that would confirm the hypothesis if prosecuted — the
    observable that separates ``confirmed`` from ``suspected`` for this claim."""

    supporting_evidence_ids: list[str] = Field(default_factory=list)
    """Ids of recorded tool-call evidence that ground an ``observed`` basis
    (proxy request ids today). Required non-empty when ``basis == observed``;
    their shape is always validated, and membership is resolved against a
    known-evidence set only when one is supplied."""

    refuting_evidence_ids: list[str] = Field(default_factory=list)
    """Ids of recorded evidence that argue against the hypothesis — the
    counter-case, kept alongside the supporting case."""

    inference_chain: list[str] = Field(default_factory=list)
    """The architecture-to-hypothesis reasoning steps for an
    ``inferred_from_architecture`` basis — each a link from the documented
    structure to the suspected weakness. Required non-empty for that basis."""

    target_depth: DepthTier | None = None
    """How far a hunt should prosecute this — ``confirm`` / ``discover`` /
    ``deep``. Depth, not grounding: this is where ambition is recorded. Every
    tier admits beginner-through-zero-day technique; ``deep`` is broader in
    scope, not merely harder."""

    impact_objective: ImpactRung | None = None
    """How far up the impact ladder a confirmed finding should be carried —
    ``reach`` → ``trigger`` → ``primitive`` → ``weaponized`` → ``chained``. The
    ladder orders consequence, not difficulty; reaching any rung may take
    anything from a textbook step to original research."""

    confidence: Confidence | None = None
    """The writer's calibrated confidence that this is real — ``low`` /
    ``medium`` / ``high``. Distinct from ``basis``: a well-grounded
    (``observed``) hypothesis can still be low-confidence, and a merely
    ``assumed`` one can be high-confidence on strong priors."""

    priority: Confidence | None = None
    """How much this is worth prosecuting relative to its siblings — ``low`` /
    ``medium`` / ``high``. Advisory; the engagement lead sets the order."""

    depends_on: list[str] = Field(default_factory=list)
    """Ids of hypotheses this one presupposes — a precondition that must hold
    before this one is reachable."""

    variant_of: str = ""
    """Id of a parent hypothesis this one is a variant of — a sibling in the
    same class's technique tree, not an independent claim."""

    owner: str = ""
    """Agent or role currently prosecuting this hypothesis, if assigned."""

    state: HypothesisState = "open"
    """Where the hypothesis stands: ``open`` (untried), ``testing`` (in
    progress), ``confirmed``, ``refuted``, or ``blocked`` (needs access or a
    precondition that is not yet met)."""

    disposition: HypothesisDisposition | None = None
    """How this lead was handled when it is left ``open``/``blocked`` at scan
    close — one of :data:`HYPOTHESIS_DISPOSITION_VALUES`. This is the inline,
    low-friction channel the finish-time closure gate accepts in place of a
    terminal (``confirmed``/``refuted``) state or a dedicated
    ``## Deferred Hypotheses`` record: an open/blocked hypothesis that carries a
    disposition counts as handled; one that carries none blocks the scan from
    finishing and is named. It records *how the lead was handled*, never a
    vulnerability class, and a terminal hypothesis needs none. Organic spellings
    (``Deferred``, ``accepted-risk``, ``out of scope``) are normalized onto the
    canonical token, and a blank value is treated as unset, not as an error."""

    disposition_reason: str = ""
    """Free-text reason for the ``disposition`` — why this open/blocked lead is
    carried forward, accepted, scoped out, or resolved elsewhere. Advisory for the
    reader and strongly encouraged, but optional: the typed ``disposition`` is
    what the closure gate reads."""

    rationale: str = ""
    """Free-text reasoning for the model's benefit — context, not contract; the
    typed fields above are what the gate reads."""

    @field_validator("supporting_evidence_ids", "refuting_evidence_ids")
    @classmethod
    def _evidence_shape(cls, value: list[str]) -> list[str]:
        return _validate_evidence_ids(value)

    @field_validator("vuln_class")
    @classmethod
    def _known_vuln_class(cls, value: str) -> str:
        """When named, the class must be one the shipped catalog carries.

        Mirrors :meth:`HuntTask._one_known_class`: an empty value is allowed
        (naming a class is optional), and when the catalog cannot be read the
        membership check is skipped rather than rejecting every class.
        """
        value = value.strip()
        if not value:
            return value
        allowed = get_vulnerability_class_names()
        if allowed and value not in allowed:
            raise ValueError(
                f"vuln_class {value!r} is not a known vulnerability class; draw it from the "
                f"vulnerabilities/* catalog: {sorted(allowed)}"
            )
        return value

    @field_validator("disposition", mode="before")
    @classmethod
    def _normalize_disposition(cls, value: object) -> str | None:
        """Accept the disposition in whatever spelling it was written; blank → unset.

        The field is typed by a hand-written markdown line, so it arrives however
        the author spelled it — ``Deferred``, ``accepted-risk``, ``out of scope``.
        Lower-casing and folding spaces and hyphens onto underscores accepts those;
        a blank value means the field was left empty, which is *no disposition*
        (``None``), not an error. A non-empty value that is not a known disposition
        then fails the typed check with a field-level message listing the valid
        values — so the closure gate stays satisfiable only by a real disposition,
        never by a typo the agent believes resolved a lead.
        """
        if value is None:
            return None
        token = str(value).strip().lower().replace("-", "_").replace(" ", "_")
        return token or None

    @model_validator(mode="after")
    def _check_grounding(self, info: ValidationInfo) -> Hypothesis:
        """Enforce the basis-conditional fields, then resolve evidence ids.

        The grounding rules are structural and always apply. Resolution mirrors
        the 1.2 ``surface_refs`` pattern: a ``known_evidence_ids`` set supplied
        through validation context is enforced as membership; with no such set
        in context the ids are shape-checked only (skip, never reject wholesale).
        """
        if self.basis == "observed" and not self.supporting_evidence_ids:
            raise ValueError(
                f"hypothesis {self.id!r}: basis 'observed' asserts a captured observation, so it "
                "requires at least one supporting_evidence_id citing the recorded tool-call "
                "evidence (e.g. a proxy request id). State the evidence, or use basis "
                "'inferred_from_architecture' / 'assumed' if the claim is not yet observed."
            )
        if self.basis == "inferred_from_architecture" and not self.inference_chain:
            raise ValueError(
                f"hypothesis {self.id!r}: basis 'inferred_from_architecture' asserts the claim is "
                "implied by the documented structure, so it requires a non-empty inference_chain "
                "laying out the architecture-to-hypothesis reasoning steps."
            )
        known = info.context.get("known_evidence_ids") if info.context else None
        if known is not None:
            known_set = set(known)
            unknown = [eid for eid in self.supporting_evidence_ids if eid not in known_set]
            if unknown:
                raise ValueError(
                    f"hypothesis {self.id!r}: supporting_evidence_ids do not resolve to recorded "
                    f"evidence: {sorted(unknown)}. Cite ids of evidence the run actually "
                    "captured (proxy request ids), not invented references."
                )
        return self


class Finding(BaseModel):
    """A candidate that a hunter raises; ``confirmed`` is unreachable without a verdict.

    Hunters produce candidates (``open`` / ``testing``). The transition to
    ``confirmed`` is a validator's call, not a hunter's: the constraint here is
    structural, so nothing can mark a finding confirmed without naming the
    verdict and who authored it. No verdict producer exists in this section, so
    in practice findings stay pre-confirmed now — the gate is the point.
    """

    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1)
    """Stable handle for this finding within the run."""

    hypothesis_id: str = ""
    """Id of the :class:`Hypothesis` this finding prosecutes, so a candidate can
    be reconciled back to the claim that motivated it."""

    title: str = ""
    """Short human-readable label."""

    state: FindingState = "open"
    """``open`` / ``testing`` — a hunter's candidate. ``confirmed`` requires a
    validator verdict (see the model constraint). ``refuted`` / ``blocked``
    otherwise."""

    validator_verdict_id: str = ""
    """Id of the validator verdict that confirmed this finding. Required
    (non-empty) for ``state == confirmed``."""

    verdict_author: str = ""
    """Id of the agent/validator that authored the verdict. Required (non-empty)
    for ``state == confirmed`` — a confirmation is attributable or it is not a
    confirmation."""

    evidence_ids: list[str] = Field(default_factory=list)
    """Ids of recorded evidence backing the finding (proxy request ids today)."""

    root_cause: str = ""
    """Why the defect exists at its source — expected once a finding is
    confirmed and filed."""

    impact_reached: ImpactRung | None = None
    """The highest impact-ladder rung actually demonstrated, not hoped for."""

    rationale: str = ""
    """Free-text reasoning; context, not contract."""

    @field_validator("evidence_ids")
    @classmethod
    def _evidence_shape(cls, value: list[str]) -> list[str]:
        return _validate_evidence_ids(value)

    @model_validator(mode="after")
    def _confirmed_needs_verdict(self) -> Finding:
        if self.state == "confirmed" and not (
            self.validator_verdict_id.strip() and self.verdict_author.strip()
        ):
            raise ValueError(
                f"finding {self.id!r}: state 'confirmed' requires both a validator_verdict_id and "
                "a verdict_author — a hunter produces candidates (state 'open'/'testing'); only a "
                "validator verdict confirms a finding, and the confirmation must be attributable."
            )
        return self


# ── parsing the convention out of the markdown ───────────────────────────────


@dataclass(frozen=True)
class HypothesisParseError:
    """One malformed hypothesis entry, named so a rejection can point at it."""

    hypothesis_id: str
    message: str


_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s")


def extract_section_body(markdown: str, aliases: Sequence[str]) -> str:
    """Return the body of the first section whose heading matches an alias.

    The body runs from just after the matched heading to the next heading of any
    level, so a subsection heading terminates it — which is what keeps a
    dedicated ``Dismissed Implied Classes`` or ``Deferred Hypotheses`` block out
    of the Hypotheses body even when it sits directly beneath it.
    """
    lines = markdown.splitlines()
    start: int | None = None
    for index, line in enumerate(lines):
        if not _HEADING_RE.match(line):
            continue
        heading = line.lstrip("#").strip().lower()
        if any(alias in heading for alias in aliases):
            start = index + 1
            break
    if start is None:
        return ""
    body: list[str] = []
    for line in lines[start:]:
        if _HEADING_RE.match(line):
            break
        body.append(line)
    return "\n".join(body)


def extract_hypotheses_section(markdown: str) -> str:
    """Return the body of the Hypotheses section (between its heading and the next)."""
    return extract_section_body(markdown, HYPOTHESES_SECTION_ALIASES)


def _entry_lines(section: str) -> list[str]:
    """List-item lines in a section body — one per hypothesis entry."""
    entries: list[str] = []
    for line in section.splitlines():
        stripped = line.strip()
        if any(stripped.startswith(bullet) for bullet in HYPOTHESIS_BULLETS):
            entries.append(stripped)
    return entries


def _parse_entry_fields(entry_line: str) -> dict[str, Any]:
    """Parse one list-item line into a field dict per the convention."""
    body = entry_line
    for bullet in HYPOTHESIS_BULLETS:
        if body.startswith(bullet):
            body = body[len(bullet) :]
            break
    fields: dict[str, Any] = {}
    for part in body.split(HYPOTHESIS_FIELD_SEP):
        key, sep, value = part.partition(HYPOTHESIS_KV_SEP)
        if not sep:
            continue
        key = key.strip().lower()
        value = value.strip()
        if not key:
            continue
        if key in ("supporting_evidence_ids", "refuting_evidence_ids", "depends_on"):
            fields[key] = [v.strip() for v in value.split(HYPOTHESIS_ID_LIST_SEP) if v.strip()]
        elif key == "inference_chain":
            fields[key] = [v.strip() for v in value.split(HYPOTHESIS_CHAIN_SEP) if v.strip()]
        else:
            fields[key] = value
    return fields


def _first_error_message(exc: Exception) -> str:
    """The most useful line from a pydantic ValidationError (or any error)."""
    errors = getattr(exc, "errors", None)
    if callable(errors):
        try:
            details = errors()
        except Exception:  # noqa: BLE001 - fall back to the string form
            details = None
        if details:
            first = details[0]
            loc = ".".join(str(part) for part in first.get("loc", ()))
            msg = str(first.get("msg", "invalid"))
            return f"{loc}: {msg}" if loc else msg
    return str(exc)


def parse_hypotheses(
    markdown: str,
    *,
    known_evidence_ids: set[str] | None = None,
) -> tuple[list[Hypothesis], list[HypothesisParseError]]:
    """Parse the Hypotheses section into validated records plus per-entry errors.

    Every list item in the section is a hypothesis entry and must satisfy the
    convention (``id`` + ``basis`` + the basis-conditional field). ``known_evidence_ids``
    is threaded into validation context: a set enforces evidence-id membership,
    ``None`` skips resolution (shape is still checked). Prose paragraphs that are
    not list items are ignored — the structured ledger is a later section.
    """
    section = extract_hypotheses_section(markdown)
    context = {"known_evidence_ids": known_evidence_ids}
    hypotheses: list[Hypothesis] = []
    errors: list[HypothesisParseError] = []
    for position, line in enumerate(_entry_lines(section), start=1):
        raw = _parse_entry_fields(line)
        label = str(raw.get("id") or f"entry #{position}")
        try:
            hypothesis = Hypothesis.model_validate(raw, context=context)
        except Exception as exc:  # noqa: BLE001 - surfaced to the caller as a named error
            errors.append(HypothesisParseError(label, _first_error_message(exc)))
        else:
            hypotheses.append(hypothesis)
    return hypotheses, errors


def referenced_evidence_ids(markdown: str) -> list[str]:
    """Every ``supporting_evidence_id`` referenced by a parseable hypothesis entry.

    Best-effort and non-raising: used by the save path to resolve referenced ids
    against the live proxy project before the authoritative parse. Entries that
    do not parse are simply skipped here; the authoritative parse names them.
    """
    section = extract_hypotheses_section(markdown)
    seen: set[str] = set()
    ordered: list[str] = []
    for line in _entry_lines(section):
        for raw in _parse_entry_fields(line).get("supporting_evidence_ids", []) or []:
            token = str(raw).strip()
            if token and token not in seen:
                seen.add(token)
                ordered.append(token)
    return ordered


# ── reasoned dismissals and deferrals (same grammar, dedicated sections) ──────
#
# Two more records live in the threat-model markdown, each parsed out of its own
# section using the *same* list-item grammar a hypothesis is written in (so there
# is one grammar, not a parallel one):
#
# * A **reasoned dismissal** records that an architecture-implied class was
#   deliberately judged not worth a hypothesis here, and why — the deliberate,
#   recorded alternative to silently omitting it. It satisfies the
#   architecture-implied-classes completeness gate alongside a hypothesis that
#   names the class.
# * A **deferral** records that an open/blocked hypothesis is being carried
#   forward explicitly rather than dropped — the recorded disposition the closure
#   gate accepts in place of a terminal (confirmed/refuted) state.
#
# Both sit in their own heading so they never parse as hypotheses, and both reuse
# ``_entry_lines`` + ``_parse_entry_fields``.


def _section_records(markdown: str, aliases: Sequence[str]) -> list[dict[str, Any]]:
    """List-item field dicts from a section, reusing the hypothesis line grammar."""
    section = extract_section_body(markdown, aliases)
    return [_parse_entry_fields(line) for line in _entry_lines(section)]


DISMISSED_CLASSES_SECTION_ALIASES: tuple[str, ...] = (
    "dismissed implied classes",
    "dismissed architecture-implied classes",
    "reasoned dismissals",
)
"""Headings that name the reasoned-dismissals section."""

DISMISSAL_LINE_EXAMPLE = (
    "- vuln_class: <class> | reason: <why this architecture-implied class is not "
    "applicable to this target>"
)
"""The dismissal grammar, shown verbatim in the generated CONTRACT and gate
rejections so the grammar taught is the grammar parsed."""


@dataclass(frozen=True)
class ClassDismissal:
    """One deliberately-recorded dismissal of an architecture-implied class."""

    vuln_class: str
    reason: str


def parse_dismissed_classes(
    markdown: str,
) -> tuple[list[ClassDismissal], list[HypothesisParseError]]:
    """Parse the reasoned-dismissals section into validated records plus errors.

    A dismissal names a ``vuln_class`` (which must be a known catalog class) and a
    non-empty ``reason``. A dismissal with neither — or an unknown class — is a
    malformed entry, named so the save gate can point at it.
    """
    allowed = get_vulnerability_class_names()
    dismissals: list[ClassDismissal] = []
    errors: list[HypothesisParseError] = []
    records = _section_records(markdown, DISMISSED_CLASSES_SECTION_ALIASES)
    for position, raw in enumerate(records, 1):
        vuln_class = str(raw.get("vuln_class", "")).strip()
        reason = str(raw.get("reason", "")).strip()
        label = vuln_class or f"dismissal #{position}"
        if not vuln_class:
            errors.append(HypothesisParseError(label, "a dismissal must name a vuln_class"))
        elif allowed and vuln_class not in allowed:
            errors.append(
                HypothesisParseError(
                    label, f"vuln_class {vuln_class!r} is not a known vulnerability class"
                )
            )
        elif not reason:
            errors.append(
                HypothesisParseError(label, "a dismissal must carry a non-empty reason")
            )
        else:
            dismissals.append(ClassDismissal(vuln_class=vuln_class, reason=reason))
    return dismissals, errors


DEFERRED_HYPOTHESES_SECTION_ALIASES: tuple[str, ...] = (
    "deferred hypotheses",
    "carried-forward hypotheses",
    "hypothesis dispositions",
)
"""Headings that name the deferrals section (the closure gate's disposition record)."""

DEFERRAL_LINE_EXAMPLE = (
    "- hypothesis_id: <id> | reason: <why this lead is carried forward rather than resolved>"
)
"""The deferral grammar, shown verbatim in the closure-gate rejection."""


@dataclass(frozen=True)
class HypothesisDeferral:
    """One open/blocked hypothesis explicitly carried forward at scan close."""

    hypothesis_id: str
    reason: str


def parse_deferrals(
    markdown: str,
) -> tuple[list[HypothesisDeferral], list[HypothesisParseError]]:
    """Parse the deferrals section into validated records plus per-entry errors.

    A deferral names the ``hypothesis_id`` being carried forward and a non-empty
    ``reason``. It is the recorded disposition the closure gate accepts for a
    hypothesis left in an open/blocked state.
    """
    deferrals: list[HypothesisDeferral] = []
    errors: list[HypothesisParseError] = []
    records = _section_records(markdown, DEFERRED_HYPOTHESES_SECTION_ALIASES)
    for position, raw in enumerate(records, 1):
        hypothesis_id = str(raw.get("hypothesis_id", "")).strip()
        reason = str(raw.get("reason", "")).strip()
        label = hypothesis_id or f"deferral #{position}"
        if not hypothesis_id:
            errors.append(HypothesisParseError(label, "a deferral must name a hypothesis_id"))
        elif not reason:
            errors.append(HypothesisParseError(label, "a deferral must carry a non-empty reason"))
        else:
            deferrals.append(HypothesisDeferral(hypothesis_id=hypothesis_id, reason=reason))
    return deferrals, errors


__all__ = [
    "BASIS_MARKER",
    "DEFERRAL_LINE_EXAMPLE",
    "DEFERRED_HYPOTHESES_SECTION_ALIASES",
    "DISMISSAL_LINE_EXAMPLE",
    "DISMISSED_CLASSES_SECTION_ALIASES",
    "DISPOSITION_CONVENTION",
    "DISPOSITION_LINE_EXAMPLE",
    "HYPOTHESES_SECTION_ALIASES",
    "HYPOTHESIS_BASIS_VALUES",
    "HYPOTHESIS_CONVENTION",
    "HYPOTHESIS_DISPOSITION_VALUES",
    "HYPOTHESIS_EXAMPLE",
    "ClassDismissal",
    "Confidence",
    "Finding",
    "FindingState",
    "Hypothesis",
    "HypothesisDeferral",
    "HypothesisDisposition",
    "HypothesisParseError",
    "HypothesisState",
    "extract_section_body",
    "parse_deferrals",
    "parse_dismissed_classes",
    "parse_hypotheses",
    "referenced_evidence_ids",
]
