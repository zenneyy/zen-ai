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
