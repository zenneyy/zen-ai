"""The validator quarantine boundary (Phase 2, item 2.2).

Section 2.2's oracle logic and the per-run ground truth it rests on are an answer
key: the agent must not read them (or it could fabricate the signal an oracle
looks for), and the 2.2 self-evolution optimizer must not read or edit them (or it
could learn or weaken the confirmation function). These assert the boundary holds,
mirroring the eval harness's own quarantine test.

Every assertion here reads tracked files but one: the optimizer's canonical no-read
list lives in the local eval harness, which git ignores. Where the harness is absent,
as in a clean checkout, that one test is skipped and says why; where it is present it
runs, and any failure to load the harness fails it.
"""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

from zen.skills import skill_search_dirs
from zen.validation.quarantine import (
    NO_READ_MARKER,
    VALIDATOR_NO_READ,
    quarantined_paths,
)


_REPO_ROOT = Path(__file__).resolve().parents[1]
_ZEN_ROOT = _REPO_ROOT / "zen"
_HARNESS_PACKAGE = "evals"
_HARNESS_QUARANTINE = _REPO_ROOT / _HARNESS_PACKAGE / "quarantine.py"


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
    if not _HARNESS_QUARANTINE.is_file():
        pytest.skip(
            "the optimizer's no-read list is in the local eval harness "
            f"({_HARNESS_QUARANTINE}), which this checkout does not hold"
        )
    harness = importlib.import_module(f"{_HARNESS_PACKAGE}.quarantine")
    joined = " ".join(harness.SELF_EVOLUTION_NO_READ)
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


def test_no_zen_module_imports_the_eval_harness() -> None:
    """The boundary's other half, checkable in every checkout: the dependency runs
    one way, so no module under zen/ imports the harness."""
    offenders = sorted(
        path.relative_to(_ZEN_ROOT.parent).as_posix()
        for path in _ZEN_ROOT.rglob("*.py")
        if _HARNESS_PACKAGE in _imported_roots(path)
    )
    assert offenders == [], f"zen modules import the eval harness: {offenders}"


def _imported_roots(path: Path) -> set[str]:
    """Top-level names a module imports with an absolute import."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    roots: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots
