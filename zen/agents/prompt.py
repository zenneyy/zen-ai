"""Jinja-based system-prompt renderer."""

from __future__ import annotations

import logging
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

from zen.agents.contract import render_contract
from zen.skills import (
    find_deep_siblings,
    get_available_skills,
    load_skills,
    skill_search_dirs,
)
from zen.tools.detected_stack.tools import max_architecture_depth
from zen.utils.resource_paths import get_zen_resource_path


logger = logging.getLogger(__name__)


_PROMPT_DIRNAME = "prompts"

# Persona skill var-name (the ``coordination/<x>_agent`` body in skill_content)
# for each role whose CONTRACT is generated. The persona files carry METHOD only;
# the CONTRACT is appended at render time from zen.agents.contract.
_PERSONA_VAR_BY_ROLE = {
    "root": "root_agent",
    "recon": "recon_agent",
    "hunter": "hunter_agent",
}


def _role_for_contract(*, is_root: bool, skill_content: dict[str, str]) -> str | None:
    """Which role's CONTRACT (if any) to generate for this prompt.

    Root is known from the flag; a recon/hunter child is known by the persona
    body the skill resolver loaded. A role without a generated CONTRACT (or a
    plain agent with no persona) returns ``None``.
    """
    if is_root:
        return "root"
    if _PERSONA_VAR_BY_ROLE["recon"] in skill_content:
        return "recon"
    if _PERSONA_VAR_BY_ROLE["hunter"] in skill_content:
        return "hunter"
    return None


def _attach_generated_contract(skill_content: dict[str, str], *, is_root: bool) -> None:
    """Append the role's generated CONTRACT to its persona METHOD body, in place.

    The persona files are METHOD-only; this is the single point where the
    obligations half is stitched on, so CONTRACT is never hand-written and never
    drifts from the gates it describes.
    """
    role = _role_for_contract(is_root=is_root, skill_content=skill_content)
    if role is None:
        return
    var = _PERSONA_VAR_BY_ROLE[role]
    method = skill_content.get(var)
    if not method:
        return
    try:
        contract = render_contract(role)
    except Exception:
        # A contract-render bug must degrade to METHOD-only, never blank the whole prompt.
        logger.exception("render_contract failed for role=%s; persona stays METHOD-only", role)
        return
    skill_content[var] = f"{method.rstrip()}\n\n{contract}"


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

    if requested or siblings_added:
        logger.info(
            "skill_resolve: requested=%s deep_siblings=%s"
            " (requested=%d +deep=%d =%d)",
            list(requested or []),
            siblings_added,
            len(requested or []),
            len(siblings_added),
            len(requested or []) + len(siblings_added),
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

    # Detected-stack framework slugs (get_detected_skill_slugs) are no longer
    # auto-injected; root passes them explicitly via create_agent's requested
    # list when relevant.  The store and helpers remain for that reactive path.

    if scan_mode == "deep" and max_architecture_depth(scan_targets) > 1:
        arch_gated = ["vulnerabilities/http_request_smuggling"]
        requested_set = set(requested or [])
        if requested_set & set(arch_gated):
            ordered.extend(arch_gated)
            ordered.extend(find_deep_siblings(arch_gated))
        else:
            logger.debug(
                "arch_gate: depth>1 but %s not in requested; skipping injection",
                arch_gated,
            )

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
        _attach_generated_contract(skill_content, is_root=is_root)
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
        # Per-skill byte-offset trace: cumulative char counts over the loaded
        # skill bodies (same strings substituted into the rendered prompt, so
        # units match prompt_len). Pure measurement — never alters ordering or
        # the rendered output.
        if skill_content:
            _offset = 0
            _parts: list[str] = []
            for _slug, _body in skill_content.items():
                _blen = len(_body)
                _parts.append(f"{_slug}@{_offset}(+{_blen})")
                _offset += _blen
            logger.debug(
                "skill_offsets: total=%d [%s]",
                _offset,
                ", ".join(_parts),
            )
        logger.debug(
            "render_system_prompt: scan_mode=%s root=%s whitebox=%s skills=%d prompt_len=%d",
            scan_mode,
            is_root,
            is_whitebox,
            len(skill_content),
            len(rendered),
        )
        return str(rendered)
