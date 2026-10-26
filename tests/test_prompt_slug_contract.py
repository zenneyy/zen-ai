"""CI contract over the orchestration surface — shipped prompt and personas (item 1.1.5).

Closes audit finding #7: the root persona used to tell root to pass
``coordination/*`` slugs that the skill validator rejects. Two guarantees are
pinned here, scoped to the text that actually drives spawn/skill decisions — the
system prompt template and the ``coordination/*`` role personas:

(a) every ``category/name`` slug those files reference either validates through
    ``validate_requested_skills`` (a caller could legitimately pass it) or is a
    real module the framework injects itself (an internal ``coordination`` /
    ``scan_modes`` / ``analysis`` module the model never needs to request); a
    dangling reference to a nonexistent slug fails.

(b) no persona or prompt instructs passing an internal module slug in ``skills``
    — i.e. no real internal-category slug appears on a line that also talks about
    ``skills``. Internal modules follow role / scan-mode / always-on wiring, not
    a requested list.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from zen.skills import _INTERNAL_SKILL_CATEGORIES, validate_requested_skills
from zen.utils.resource_paths import get_zen_resource_path


if TYPE_CHECKING:
    from pathlib import Path


_SKILLS_DIR = get_zen_resource_path("skills")
_SYSTEM_PROMPT = get_zen_resource_path("agents", "prompts") / "system_prompt.jinja"

# Backtick-wrapped category/name slug. The name class excludes ``*`` so glob
# patterns like ``tooling/*`` / ``vulnerabilities/*`` in prose are not slugs.
_SLUG_RE = re.compile(r"`([a-z_]+)/([a-z0-9_]+)`")
# A real internal-category module reference (backtick optional), for check (b).
_INTERNAL_SLUG_RE = re.compile(
    r"(" + "|".join(sorted(_INTERNAL_SKILL_CATEGORIES)) + r")/([a-z0-9_]+)"
)


def _orchestration_files() -> list[Path]:
    files = [_SYSTEM_PROMPT, *sorted((_SKILLS_DIR / "coordination").glob("*.md"))]
    return [f for f in files if f.is_file()]


def _is_real_module(slug: str) -> bool:
    return (_SKILLS_DIR / f"{slug}.md").is_file()


def test_orchestration_files_are_present() -> None:
    files = _orchestration_files()
    assert _SYSTEM_PROMPT in files
    # The three role personas (plus source_aware_whitebox) ship under coordination/.
    names = {f.name for f in files}
    assert {"root_agent.md", "recon_agent.md", "hunter_agent.md"} <= names


def test_every_referenced_slug_validates_or_is_framework_injected() -> None:
    offenders: list[str] = []
    for path in _orchestration_files():
        for category, name in _SLUG_RE.findall(path.read_text(encoding="utf-8")):
            slug = f"{category}/{name}"
            passable = validate_requested_skills([slug]) is None
            framework_injected = category in _INTERNAL_SKILL_CATEGORIES and _is_real_module(slug)
            if not (passable or framework_injected):
                offenders.append(f"{path.name}: {slug}")
    assert not offenders, (
        "Shipped orchestration text references slugs that neither validate nor name a "
        f"real framework-injected module (dangling references): {offenders}"
    )


def test_no_persona_instructs_passing_an_internal_slug_in_skills() -> None:
    offenders: list[str] = []
    for path in _orchestration_files():
        for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if "skill" not in line.lower():
                continue
            for category, name in _INTERNAL_SLUG_RE.findall(line):
                slug = f"{category}/{name}"
                if _is_real_module(slug):
                    offenders.append(f"{path.name}:{lineno}: {slug}")
    assert not offenders, (
        "Shipped orchestration text names an internal module slug on a line about `skills` "
        "— internal modules are attached by role/scan-mode, never requested: " + str(offenders)
    )
