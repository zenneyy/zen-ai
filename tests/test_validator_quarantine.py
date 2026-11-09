"""The validator quarantine boundary (Phase 2, item 2.2).

Section 2.2's oracle logic and the per-run ground truth it rests on are an answer
key: the agent must not read them (or it could fabricate the signal an oracle
looks for), and the 2.2 self-evolution optimizer must not read or edit them (or it
could learn or weaken the confirmation function). These assert the boundary holds,
mirroring the eval harness's own quarantine test.
"""

from __future__ import annotations

from pathlib import Path

from evals.quarantine import SELF_EVOLUTION_NO_READ
from zen.skills import skill_search_dirs
from zen.validation.quarantine import (
    NO_READ_MARKER,
    VALIDATOR_NO_READ,
    quarantined_paths,
)


def test_every_quarantined_file_carries_the_no_read_marker() -> None:
    assert VALIDATOR_NO_READ  # non-empty
    for path in quarantined_paths():
        assert path.is_file(), f"quarantined file missing: {path}"
        assert NO_READ_MARKER in path.read_text(encoding="utf-8"), (
            f"{path} does not carry the quarantine marker {NO_READ_MARKER!r}"
        )


def test_the_optimizer_no_read_list_covers_every_validator_path() -> None:
    """The validator oracle/ground-truth is outside the 2.2 optimizer's reach:
    every quarantined path is on the optimizer's canonical no-read list."""
    joined = " ".join(SELF_EVOLUTION_NO_READ)
    for rel in VALIDATOR_NO_READ:
        assert rel in joined, f"{rel} is not on the optimizer no-read list"


def test_the_validator_package_is_not_a_skill_search_directory() -> None:
    """The validator is not loadable as a skill, so it can never be rendered into
    a persona or the agent's context."""
    validation_root = Path(__file__).resolve().parents[1] / "zen" / "validation"
    for directory in skill_search_dirs():
        resolved = Path(directory).resolve()
        assert validation_root not in resolved.parents and resolved != validation_root, (
            f"zen/validation is on the skill search path ({resolved})"
        )


def test_the_validator_package_contributes_no_agent_tool() -> None:
    """No `@function_tool` lives in the validator package — it is a verdict
    producer the framework calls, never a tool the agent can invoke."""
    validation_root = Path(__file__).resolve().parents[1] / "zen" / "validation"
    offenders: list[str] = []
    for path in validation_root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        if "@function_tool" in text:
            offenders.append(path.name)
    assert offenders == [], f"validator package exposes agent tools: {offenders}"
