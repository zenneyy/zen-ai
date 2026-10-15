"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from zen.skills import (
    find_deep_siblings,
    find_related_skills,
    get_available_skills,
    load_skills,
    skill_search_dirs,
)
from zen.tools.detected_stack.tools import get_detected_skill_slugs, max_architecture_depth
from zen.utils.resource_paths import get_zen_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"


def _resolve_skills(
    *,
    requested: list[str] | None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    is_diff_scoped: bool = False,
    scan_targets: list[str] | None = None,
) -> list[str]:
    """Build the deduped, ordered skills list for the prompt render.

    Order:

    1. Whatever the caller asked for, in order.
    2. In deep mode only: any sibling skills matching the naming
       convention ``<base>_<topic>_deep.md`` in the same category
       directory as each requested skill.
    3. ``scan_modes/<mode>`` (always), plus ``scan_modes/diff`` when the
       run is scoped to a change set — diff scope overlays the depth
       mode rather than replacing it.
    4. ``tooling/agent_browser`` (always — every agent has shell + the
       agent-browser CLI).
    5. ``tooling/python`` (always — Python runs through ``exec_command``;
       sandbox scripts can import ``caido_api`` for Caido automation).
    6. ``analysis/counterevidence`` and ``analysis/severity_calibration``
       (always — closure discipline and severity rubric apply to every
       agent that can open or close a candidate, or file a report).
    7. ``coordination/root_agent`` for the root agent only — orchestration
       guidance for delegating to specialist subagents.
    8. Whitebox-specific skills if applicable, including
       ``analysis/fix_verification`` (only whitebox agents can attach an
       applyable ``fix_after``) and ``analysis/source_aware_discovery``.
    """
    ordered: list[str] = list(requested or [])

    # In deep mode, automatically load sibling skills matching the naming
    # convention <base>_<topic>_deep.md. This ensures advanced-technique
    # skills (asset_discovery_cloud_deep, application_enumeration_api_deep,
    # etc.) are loaded alongside their base skill without requiring hardcoded
    # per-agent skill lists in coordinators or factories.
    if scan_mode == "deep" and requested:
        ordered.extend(find_deep_siblings(requested))

    siblings_added = [s for s in ordered if s not in set(requested or [])]

    pre_related = len(ordered)
    if requested:
        ordered.extend(find_related_skills(requested))
    related_added = ordered[pre_related:]

    tooling_requested = [s for s in (requested or []) if s.startswith("tooling/")]
    tooling_related = [s for s in related_added if s.startswith("tooling/")]

    if requested or siblings_added or related_added:
        logger.info(
            "skill_resolve: requested=%s deep_siblings=%s"
            " tooling_requested=%s tooling_related=%s"
            " (requested=%d +deep=%d +tooling=%d +rest=%d =%d)",
            list(requested or []),
            siblings_added,
            tooling_requested,
            tooling_related,
            len(requested or []),
            len(siblings_added),
            len(tooling_requested) + len(tooling_related),
            len(related_added) - len(tooling_related),
            len(requested or []) + len(siblings_added) + len(related_added),
        )

    ordered.append(f"scan_modes/{scan_mode}")
    if is_diff_scoped:
        ordered.append("scan_modes/diff")
    ordered.append("tooling/agent_browser")
    ordered.append("tooling/python")
    ordered.append("analysis/counterevidence")
    ordered.append("analysis/severity_calibration")
    if scan_mode == "deep":
        ordered.append("validation/red_team_the_finding")
        ordered.append("validation/negative_control_design")
        ordered.append("validation/fp_taxonomy")
        ordered.append("validation/blind_revalidation")
    if is_root:
        ordered.append("coordination/root_agent")
        if scan_mode == "deep":
            ordered.append("chaining/chain_construction")
            ordered.append("chaining/chain_severity")
            ordered.append("chaining/chain_validation")
            ordered.append("chaining/primitive_taxonomy")
    if is_whitebox:
        ordered.append("coordination/source_aware_whitebox")
        ordered.append("custom/source_aware_sast")
        ordered.append("analysis/source_aware_discovery")
        ordered.append("analysis/fix_verification")

    if scan_mode == "deep":
        ordered.extend(get_detected_skill_slugs(scan_targets))

    if scan_mode == "deep" and max_architecture_depth(scan_targets) > 1:
        arch_gated = ["vulnerabilities/http_request_smuggling"]
        ordered.extend(arch_gated)
        ordered.extend(find_deep_siblings(arch_gated))
        ordered.extend(find_related_skills(arch_gated))

    deduped: list[str] = []
    seen: set[str] = set()
    for skill in ordered:
        if skill and skill not in seen:
            deduped.append(skill)
            seen.add(skill)
    return deduped


def render_system_prompt(
    *,
    skills: list[str] | None = None,
    scan_mode: str = "deep",
    is_whitebox: bool = False,
    is_root: bool = False,
    is_diff_scoped: bool = False,
    interactive: bool = False,
    system_prompt_context: dict[str, Any] | None = None,
    scan_targets: list[str] | None = None,
) -> str:
    """Render the system prompt. Returns empty string on template failure."""
    try:
        prompt_dir = get_zen_resource_path("agents", _PROMPT_DIRNAME)
        loader_dirs = [prompt_dir, *skill_search_dirs()]
        env = Environment(
            loader=FileSystemLoader(loader_dirs),
            autoescape=select_autoescape(
                enabled_extensions=(),
                default_for_string=False,
            ),
        )

        skills_to_load = _resolve_skills(
            requested=skills,
            scan_mode=scan_mode,
            is_whitebox=is_whitebox,
            is_root=is_root,
            is_diff_scoped=is_diff_scoped,
            scan_targets=scan_targets,
        )
        skill_content = load_skills(skills_to_load)
        env.globals["get_skill"] = lambda name: skill_content.get(name, "")

        rendered = env.get_template("system_prompt.jinja").render(
            loaded_skill_names=list(skill_content.keys()),
            available_skills=get_available_skills(),
            interactive=interactive,
            is_root=is_root,
            system_prompt_context=system_prompt_context or {},
            **skill_content,
        )
    except Exception:
        logger.exception("render_system_prompt failed; returning empty prompt")
        return ""
    else:
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)
