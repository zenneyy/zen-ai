"""Detected-stack store — technology fingerprints per target.

The recon agent registers which frameworks, protocols, and technologies it
identified during fingerprinting.  Specialist agents spawned afterwards
deterministically receive the matching skill playbooks at prompt-render
time, without relying on the root model to pass them explicitly.

Mirrors the threat-model store pattern: module-global dict keyed by
normalized target identity, thread-safe, mirrored to the run's state
directory for resume.

Cloud providers (aws/gcp/azure/kubernetes) are intentionally excluded —
they are loaded reactively via ``load_skill`` when SSRF confirms
metadata-endpoint access, not at spawn time.
"""

from __future__ import annotations

import asyncio
import json
import logging
import tempfile
import threading
from pathlib import Path
from typing import Any

from agents import RunContextWrapper, function_tool
from pydantic import BaseModel, Field

from zen.skills import _candidate_skill_files
from zen.tools.threat_model.tools import _resolve_target, _target_identity


logger = logging.getLogger(__name__)

_VALID_NAMESPACES: frozenset[str] = frozenset({
    "frameworks",
    "protocols",
    "technologies",
})

_store_lock = threading.RLock()
_DETECTED_STACK: dict[str, dict[str, list[str]]] = {}
_store_path: Path | None = None


def _slug_resolves(namespace: str, slug: str) -> bool:
    return bool(_candidate_skill_files(f"{namespace}/{slug}"))


def hydrate_detected_stack_from_disk(state_dir: Path) -> None:
    """Load a persisted detected-stack from a previous or resumed run."""
    global _store_path  # noqa: PLW0603
    _store_path = state_dir / "detected_stack.json"
    with _store_lock:
        _DETECTED_STACK.clear()
        if not _store_path.is_file():
            return
        try:
            data = json.loads(_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "detected_stack.json at %s is unreadable; starting empty",
                _store_path,
            )
            return
        if not isinstance(data, dict):
            return
        for identity, stacks in data.items():
            if not isinstance(identity, str) or not isinstance(stacks, dict):
                continue
            _DETECTED_STACK[identity] = {
                ns: slugs
                for ns, slugs in stacks.items()
                if isinstance(ns, str)
                and ns in _VALID_NAMESPACES
                and isinstance(slugs, list)
            }
        logger.info(
            "detected stack hydrated from %s (%d target(s))",
            _store_path,
            len(_DETECTED_STACK),
        )


def _persist_locked() -> None:
    """Mirror the store to disk.  Caller must hold ``_store_lock``."""
    path = _store_path
    if path is None:
        return
    try:
        payload = json.dumps(_DETECTED_STACK, ensure_ascii=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except OSError:
        logger.exception("detected stack mirror to %s failed", path)


def _scan_targets(ctx: RunContextWrapper) -> list[str]:
    inner = ctx.context if isinstance(ctx.context, dict) else {}
    targets = inner.get("scan_targets")
    if not isinstance(targets, list):
        return []
    return [t for t in targets if isinstance(t, str) and t.strip()]


def _register_impl(
    target: str,
    *,
    frameworks: list[str],
    protocols: list[str],
    technologies: list[str],
    scan_targets: list[str] | None = None,
) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    identity = _target_identity(resolved)

    incoming: dict[str, list[str]] = {
        "frameworks": frameworks,
        "protocols": protocols,
        "technologies": technologies,
    }

    accepted: dict[str, list[str]] = {}
    rejected: list[str] = []

    for namespace in sorted(_VALID_NAMESPACES):
        for raw_slug in incoming.get(namespace, []):
            slug = raw_slug.strip().lower()
            if not slug:
                continue
            if _slug_resolves(namespace, slug):
                accepted.setdefault(namespace, []).append(slug)
            else:
                rejected.append(f"{namespace}/{slug}")
                logger.warning(
                    "register_detected_stack: rejected unknown slug %s/%s",
                    namespace,
                    slug,
                )

    with _store_lock:
        existing = _DETECTED_STACK.setdefault(identity, {})
        for ns, slugs in accepted.items():
            merged = list(dict.fromkeys([*existing.get(ns, []), *slugs]))
            existing[ns] = merged
        _persist_locked()

    logger.info(
        "register_detected_stack: target=%s frameworks=%s protocols=%s technologies=%s",
        identity,
        accepted.get("frameworks", []),
        accepted.get("protocols", []),
        accepted.get("technologies", []),
    )

    result: dict[str, Any] = {
        "success": True,
        "target": identity,
        "registered": accepted,
    }
    if rejected:
        result["rejected"] = rejected
        result["warning"] = (
            f"Dropped unknown slugs (no matching skill file): {rejected}"
        )
    return result


def read_detected_stack(
    target: str,
    scan_targets: list[str] | None = None,
) -> dict[str, list[str]]:
    """Read the detected stack for one target.  Empty dict if none."""
    resolved, _ = _resolve_target(target, scan_targets)
    if resolved is None:
        return {}
    identity = _target_identity(resolved)
    with _store_lock:
        entry = _DETECTED_STACK.get(identity)
        return dict(entry) if entry else {}


def get_detected_skill_slugs(
    scan_targets: list[str] | None = None,
) -> list[str]:
    """Qualified slugs for all scan targets, deduped and ordered.

    Returns e.g. ``["frameworks/flask", "protocols/graphql"]``.
    Cloud namespaces are never included.
    """
    with _store_lock:
        if not scan_targets:
            entries = list(_DETECTED_STACK.values())
        else:
            entries = []
            for target in scan_targets:
                resolved, _ = _resolve_target(target, scan_targets)
                if resolved is None:
                    continue
                identity = _target_identity(resolved)
                entry = _DETECTED_STACK.get(identity)
                if entry:
                    entries.append(entry)

    result: list[str] = []
    seen: set[str] = set()
    for entry in entries:
        for ns in sorted(_VALID_NAMESPACES):
            for slug in entry.get(ns, []):
                qualified = f"{ns}/{slug}"
                if qualified not in seen:
                    result.append(qualified)
                    seen.add(qualified)
    return result


@function_tool(timeout=30)
async def register_detected_stack(
    ctx: RunContextWrapper,
    frameworks: list[str] | None = None,
    protocols: list[str] | None = None,
    technologies: list[str] | None = None,
    target: str = "",
) -> str:
    """Register the technology stack detected during recon fingerprinting.

    Call this after running ``httpx -td`` (tech-detect) and probing
    endpoints.  Map observed signals to bare slugs within each namespace:

    - **frameworks**: Werkzeug / ``session=`` cookie → ``flask``;
      ``csrfmiddlewaretoken`` / Django admin → ``django``;
      ``__next`` cookie / ``/_next/`` paths → ``nextjs``;
      ``X-Powered-By: Express`` → ``express``;
      ``X-Powered-By: PHP`` + Laravel patterns → ``laravel``;
      Spring ``JSESSIONID`` / ``/actuator`` → ``spring``.
    - **protocols**: ``/graphql`` introspection responds → ``graphql``;
      ``/.well-known/openid-configuration`` / OAuth flow → ``oauth``.
    - **technologies**: Firebase domains in JS → ``firebase``;
      Auth0 tenant in login flow → ``auth0``;
      Supabase URLs/keys in client → ``supabase``;
      Prometheus/Grafana endpoints → ``grafana_prometheus``;
      LLM API endpoints → ``llm_applications``.

    Only register what is **actually observed** — fingerprinting
    evidence, not guesses.  Each slug must match a real skill file;
    unknown slugs are silently dropped with a warning.

    Cloud providers (``aws``, ``gcp``, ``azure``, ``kubernetes``) are
    **not** registered here — they are loaded reactively via
    ``load_skill`` when SSRF confirms metadata-endpoint access.

    Args:
        frameworks: Bare slugs in the ``frameworks/`` namespace.
        protocols: Bare slugs in the ``protocols/`` namespace.
        technologies: Bare slugs in the ``technologies/`` namespace.
        target: The target these technologies were detected on.  If
            omitted and the scan has a single target, that target is
            used.
    """
    return json.dumps(
        await asyncio.to_thread(
            _register_impl,
            target,
            frameworks=list(frameworks or []),
            protocols=list(protocols or []),
            technologies=list(technologies or []),
            scan_targets=_scan_targets(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )


# ── Architecture (ordered request-path) store ────────────────────────
#
# Sibling to _DETECTED_STACK.  Holds the ordered sequence of processing
# stages (hops) a request traverses, front-to-back.  Each hop is a dict
# with at minimum {"name": "<label>"}; an optional "role" field describes
# the hop's function.  Depth = len(hops) = node count.
#
# This store is data, not skill slugs — hops never feed the slug→file
# pipeline.

_DETECTED_ARCHITECTURE: dict[str, list[dict[str, str]]] = {}
_arch_store_path: Path | None = None


def hydrate_architecture_from_disk(state_dir: Path) -> None:
    """Load a persisted architecture store from a previous or resumed run."""
    global _arch_store_path  # noqa: PLW0603
    _arch_store_path = state_dir / "detected_architecture.json"
    with _store_lock:
        _DETECTED_ARCHITECTURE.clear()
        if not _arch_store_path.is_file():
            return
        try:
            data = json.loads(_arch_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "detected_architecture.json at %s is unreadable; starting empty",
                _arch_store_path,
            )
            return
        if not isinstance(data, dict):
            return
        for identity, hops in data.items():
            if not isinstance(identity, str) or not isinstance(hops, list):
                continue
            if all(isinstance(h, dict) for h in hops):
                _DETECTED_ARCHITECTURE[identity] = hops
        logger.info(
            "architecture store hydrated from %s (%d target(s))",
            _arch_store_path,
            len(_DETECTED_ARCHITECTURE),
        )


def _persist_architecture_locked() -> None:
    """Mirror the architecture store to disk.  Caller must hold ``_store_lock``."""
    path = _arch_store_path
    if path is None:
        return
    try:
        payload = json.dumps(_DETECTED_ARCHITECTURE, ensure_ascii=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=str(path.parent),
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as tmp:
            tmp.write(payload)
            tmp_path = Path(tmp.name)
        tmp_path.replace(path)
    except OSError:
        logger.exception("architecture store mirror to %s failed", path)


def _register_architecture_impl(
    target: str,
    *,
    hops: list[dict[str, str]],
    scan_targets: list[str] | None = None,
) -> dict[str, Any]:
    resolved, error = _resolve_target(target, scan_targets)
    if resolved is None:
        return {"success": False, "error": error}

    identity = _target_identity(resolved)

    if not isinstance(hops, list) or not all(isinstance(h, dict) for h in hops):
        return {
            "success": False,
            "error": "hops must be a list of dicts, each with at least a 'name' key.",
        }
    if not all(isinstance(h.get("name"), str) and h["name"].strip() for h in hops):
        return {
            "success": False,
            "error": "Every hop must have a non-empty 'name' string.",
        }

    cleaned: list[dict[str, str]] = [
        {k: v for k, v in h.items() if isinstance(k, str) and isinstance(v, str)}
        for h in hops
    ]

    with _store_lock:
        _DETECTED_ARCHITECTURE[identity] = cleaned
        _persist_architecture_locked()

    logger.info(
        "register_architecture: target=%s depth=%d hops=%s",
        identity,
        len(cleaned),
        [h.get("name") for h in cleaned],
    )

    return {
        "success": True,
        "target": identity,
        "depth": len(cleaned),
        "hops": cleaned,
    }


def read_architecture(
    target: str,
    scan_targets: list[str] | None = None,
) -> list[dict[str, str]]:
    """Ordered hop list for one target.  Empty list if none registered."""
    resolved, _ = _resolve_target(target, scan_targets)
    if resolved is None:
        return []
    identity = _target_identity(resolved)
    with _store_lock:
        entry = _DETECTED_ARCHITECTURE.get(identity)
        return list(entry) if entry else []


def architecture_depth(
    target: str,
    scan_targets: list[str] | None = None,
) -> int:
    """Node count for one target's request path.  0 if none registered."""
    return len(read_architecture(target, scan_targets))


def max_architecture_depth(
    scan_targets: list[str] | None = None,
) -> int:
    """Maximum architecture depth across all scan targets."""
    with _store_lock:
        if not scan_targets:
            entries = list(_DETECTED_ARCHITECTURE.values())
        else:
            entries = []
            for target in scan_targets:
                resolved, _ = _resolve_target(target, scan_targets)
                if resolved is None:
                    continue
                identity = _target_identity(resolved)
                entry = _DETECTED_ARCHITECTURE.get(identity)
                if entry:
                    entries.append(entry)
    if not entries:
        return 0
    return max(len(e) for e in entries)


class ArchitectureHop(BaseModel):
    """A single processing stage in the request path."""

    name: str = Field(description="Short label for this processing stage.")
    role: str = Field(default="", description="What function this stage serves.")


@function_tool(timeout=30)
async def register_architecture(
    ctx: RunContextWrapper,
    hops: list[ArchitectureHop],
    target: str = "",
) -> str:
    """Register the ordered request path observed during reconnaissance.

    Call this after mapping how a request traverses processing stages
    from the outermost entry point to the final handler.  Pass the
    stages in order, front-most first.

    Each hop has:

    - ``name`` (required): a short label for this processing stage.
    - ``role`` (optional): what function this stage serves.

    Example (generic — use whatever labels match what you observe)::

        hops=[
            {"name": "<front>", "role": "entry point"},
            {"name": "<middle>", "role": "routing / rewriting"},
            {"name": "<back>", "role": "application handler"},
        ]

    Depth (the number of processing stages) is derived from the hop
    count.  A depth greater than 1 means the request passes through
    multiple stages in sequence, which widens the boundary attack
    surface.

    Args:
        hops: Ordered list of processing stages, front-most first.
        target: The target this architecture was observed on.  If
            omitted and the scan has a single target, that target is
            used.
    """
    return json.dumps(
        await asyncio.to_thread(
            _register_architecture_impl,
            target,
            hops=[h.model_dump() for h in (hops or [])],
            scan_targets=_scan_targets(ctx),
        ),
        ensure_ascii=False,
        default=str,
    )
