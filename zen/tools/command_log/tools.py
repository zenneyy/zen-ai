"""Run-scoped command log — records shell commands agents execute.

Mirrors the detected-stack / threat-model store pattern: module-global
list guarded by a lock, mirrored to the run's state directory for
resume.  The log is append-only within a run and exists so that
downstream gates can verify a specific class of command was actually
executed, rather than relying on an agent's self-report.
"""

from __future__ import annotations

import json
import logging
import re
import tempfile
import threading
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_store_lock = threading.RLock()
_COMMAND_LOG: list[str] = []
_store_path: Path | None = None

_DISCOVERY_TOOLS: frozenset[str] = frozenset({
    "feroxbuster",
    "ffuf",
    "dirsearch",
    "katana",
    "gospider",
    "hakrawler",
    "gobuster",
    "wfuzz",
})

_DISCOVERY_PATTERN: re.Pattern[str] = re.compile(
    r"\b(" + "|".join(re.escape(t) for t in sorted(_DISCOVERY_TOOLS)) + r")\b",
)


# ── persistence ─────────────────────────────────────────────────────


def hydrate_command_log_from_disk(state_dir: Path) -> None:
    """Load a persisted command log from a previous or resumed run."""
    global _store_path  # noqa: PLW0603
    _store_path = state_dir / "command_log.json"
    with _store_lock:
        _COMMAND_LOG.clear()
        if not _store_path.is_file():
            return
        try:
            data = json.loads(_store_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.exception(
                "command_log.json at %s is unreadable; starting empty",
                _store_path,
            )
            return
        if not isinstance(data, list):
            return
        for entry in data:
            if isinstance(entry, str) and entry.strip():
                _COMMAND_LOG.append(entry)
        logger.info(
            "command log hydrated from %s (%d command(s))",
            _store_path,
            len(_COMMAND_LOG),
        )


def _persist_locked() -> None:
    """Mirror the command log to disk.  Caller must hold ``_store_lock``."""
    path = _store_path
    if path is None:
        return
    try:
        payload = json.dumps(_COMMAND_LOG, ensure_ascii=False)
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
        logger.exception("command log mirror to %s failed", path)


# ── recording ───────────────────────────────────────────────────────


def record_command(cmd: str) -> None:
    """Append a shell command to the run-scoped log."""
    cmd = (cmd or "").strip()
    if not cmd:
        return
    with _store_lock:
        _COMMAND_LOG.append(cmd)
        _persist_locked()


# ── querying ────────────────────────────────────────────────────────


def has_discovery_command(host: str) -> bool:
    """True if a content/route-discovery command targeting *host* was logged.

    A command qualifies when it invokes a recognised discovery tool
    **and** its argument list contains the host string, so running
    discovery against an unrelated host does not satisfy the check.
    """
    host_lower = host.strip().lower()
    if not host_lower:
        return False
    with _store_lock:
        for cmd in _COMMAND_LOG:
            lowered = cmd.lower()
            if _DISCOVERY_PATTERN.search(lowered) and host_lower in lowered:
                return True
    return False


def logged_commands() -> list[str]:
    """Return a snapshot of the command log (testing / diagnostics)."""
    with _store_lock:
        return list(_COMMAND_LOG)
