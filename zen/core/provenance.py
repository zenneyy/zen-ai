"""What produced a run, recorded once at scan start beside the run's artifacts.

A run folder has to name the code, sandbox image, runtime and settings that
produced it, or nothing measured from it can be tied to a change.
:func:`capture_provenance` reads each of them; a value it cannot determine is
recorded as ``{"unknown": "<reason>"}``, never guessed, and a file it fails to read
costs only that file's own value. It records no environment variable, credential
file or key, and nothing that depends on where the checkout is. Of an untracked
file it records presence and a digest, never content. A symbolic link is one entry
of its own, never walked or opened; no path with a part that starts with a dot and
nothing outside the checkout is opened; what the interpreter, a developer tool or a
scan writes is ignored. Every git call runs without any ``GIT_*`` variable of zen's
environment and with the file-system monitor switched off, so neither the
environment nor a repository setting can point a read at another repository or
turn it into a command. Of a local endpoint's health reply it keeps only named
fields. The model endpoint and the stream-idle limit come from the model
provider's own resolution, and the installed environment is recorded as a whole.

:func:`record_run_provenance` writes the block to its own file in the run
directory before any agent starts. The file is ASCII, so a file name that is not
valid UTF-8 is kept as an escape; it is created exclusively and never rewritten,
and ``run.json`` names it with its digest and a summary in counts. Nothing here can
fail a scan: a failure is one warning line naming its cause, and the run goes on
with nothing named in ``run.json``.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import re
import shutil
import subprocess
from datetime import UTC, datetime
from importlib import metadata
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final
from urllib.parse import urlsplit

import httpx

import zen
from zen.config import codex
from zen.config.models import _LOOPBACK_HOSTS
from zen.core.paths import RUNS_DIR_NAME
from zen.report.state import get_global_report_state


if TYPE_CHECKING:
    from collections.abc import Callable
    from urllib.parse import SplitResult


logger = logging.getLogger(__name__)

PROVENANCE_SCHEMA_VERSION: Final = 1
PROVENANCE_FILENAME: Final = "provenance.json"

#: The imported zen package, read when a scan starts. A test points it elsewhere.
DEFAULT_PACKAGE_DIR: Path = Path(zen.__file__).resolve().parent

_CREATE_MODE: Final = "xb"
_MAX_RECORDS: Final = 100
# Every git call takes no optional lock and never starts a file-system monitor.
_GIT_OPTIONS: Final = ("--no-optional-locks", "-c", "core.fsmonitor=false")
_GIT_TIMEOUT_S: Final = 10
_HEALTH_TIMEOUT_S: Final = 2.0
# The only fields of a local endpoint's health reply whose values are kept. The
# names of any other fields are listed, so a reader knows more was declared.
_HEALTH_FIELDS: Final = ("status", "turn_timeout_s")
# Untracked files of these kinds are code, prompt templates or skills that zen can
# load, and they are hashed. Any other untracked file is counted, never opened.
_HASHED_SUFFIXES: Final = frozenset({".py", ".pyc", ".pyi", ".jinja", ".j2", ".md"})
_CACHE_DIR: Final = "__pycache__"
# A folder holding one of these is a tool cache or a virtual environment.
_GENERATED_MARKERS: Final = ("CACHEDIR.TAG", "pyvenv.cfg")
_MAX_HASHED_BYTES: Final = 64 * 1024 * 1024
# A failure to examine, size or read one file costs only that file's own value.
_READ_ERRORS: Final = (OSError,)
_LIBRARIES: Final = ("openai-agents", "openai", "litellm", "claude-agent-sdk")
_NAME_SEPARATORS: Final = re.compile(r"[-_.]+")
_CLI_VERSION_FILE: Final = "claude_agent_sdk/_cli_version.py"
_CLI_VERSION: Final = re.compile(r"__cli_version__\s*=\s*['\"]([^'\"]+)['\"]")


def unknown(reason: str) -> dict[str, str]:
    """The record of a value that could not be determined, and why."""
    return {"unknown": reason}


def _known(value: Any) -> Any:
    """``value``, or None when it is an unknown."""
    return None if isinstance(value, dict) and set(value) == {"unknown"} else value


def _field(collect: Callable[..., dict[str, Any]], *args: Any) -> dict[str, Any]:
    """One section of the record; a collector that fails yields an unknown."""
    try:
        return collect(*args)
    except Exception as exc:  # noqa: BLE001 - provenance never fails a scan
        name = getattr(collect, "__name__", "collector")
        logger.debug("provenance: %s failed", name, exc_info=True)
        return unknown(f"{name} failed: {type(exc).__name__}")


def _value(read: Callable[[], Any]) -> Any:
    """One setting, or an unknown when it cannot be read or is not set."""
    try:
        value = read()
    except Exception as exc:  # noqa: BLE001 - one unreadable setting is an unknown
        return unknown(f"not readable: {type(exc).__name__}")
    return unknown("not set") if value is None else value


# ── the zen package and its working tree ─────────────────────────────────────


def _git_environment() -> dict[str, str]:
    """Zen's environment without any GIT_* variable: nothing in it can point a read at
    another repository or inject configuration."""
    return {name: value for name, value in os.environ.items() if not name.startswith("GIT_")}


def _git(root: Path, *args: str) -> str | None:
    """Output of a read-only git command in ``root``; None when it fails."""
    try:
        done = subprocess.run(  # noqa: S603
            ["git", *_GIT_OPTIONS, "-C", str(root), *args],  # noqa: S607
            capture_output=True,
            check=False,
            timeout=_GIT_TIMEOUT_S,
            env=_git_environment(),
        )
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    return done.stdout.decode("utf-8", errors="surrogateescape")


def _names(output: str) -> list[str]:
    return sorted(name for name in output.split("\0") if name)


def _file_digest(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def _not_read(exc: OSError) -> dict[str, str]:
    """The value of a file that could not be examined or read, naming why."""
    return unknown(f"not read: {type(exc).__name__}")


def _hidden(relative: Path) -> bool:
    """Whether any part of a path starts with a dot; such a path is never opened."""
    return any(part.startswith(".") for part in relative.parts)


def _inside(root: Path, path: Path) -> bool:
    """Not a symbolic link, and inside the checkout: a link is never followed."""
    return not path.is_symlink() and path.resolve().is_relative_to(root.resolve())


def _source(package_dir: Path) -> dict[str, Any]:
    """The imported zen package: its version, the commit it came from and its tree,
    with nothing that depends on where the checkout is."""
    record: dict[str, Any] = {"version": _version("zen-agent")}
    root = package_dir.parent
    if shutil.which("git") is None:
        return {**record, **_not_a_checkout("git is not on PATH")}
    top = _git(root, "rev-parse", "--show-toplevel")
    if top is None or Path(top.strip()).resolve() != root.resolve():
        return {**record, **_not_a_checkout("the package is not at the top of a git checkout")}
    head = _git(root, "rev-parse", "--verify", "HEAD")
    modified = _modified_tracked(root)
    untracked = _untracked_code(root, package_dir)
    return {
        **record,
        "commit": head.strip() if head else unknown("the checkout has no commit at HEAD"),
        "commit_from": "git checkout",
        "tree": {
            "modified": _tree_modified(modified, untracked),
            "modified_tracked": modified,
            "untracked_code": untracked,
        },
    }


def _tree_modified(*lists: list[dict[str, Any]] | dict[str, str]) -> bool | dict[str, str]:
    """Whether the tree differs from its commit: true when a list names any path, false
    only when every list is known and empty, and an unknown otherwise."""
    if any(isinstance(found, list) and found for found in lists):
        return True
    if all(isinstance(found, list) for found in lists):
        return False
    return unknown("not every local change could be listed")


def _not_a_checkout(reason: str) -> dict[str, Any]:
    installed = _installed_commit()
    return {
        "commit": installed or unknown(reason),
        "commit_from": "installer record" if installed else unknown(reason),
        "tree": unknown(reason),
    }


def _installed_commit() -> str | None:
    """The commit an installer recorded for zen-agent (PEP 610), if it recorded one."""
    try:
        text = metadata.distribution("zen-agent").read_text("direct_url.json") or "{}"
        commit = json.loads(text).get("vcs_info", {}).get("commit_id")
    except (metadata.PackageNotFoundError, ValueError, AttributeError):
        return None
    return commit if isinstance(commit, str) and commit else None


def _modified_tracked(root: Path) -> list[dict[str, Any]] | dict[str, str]:
    """Tracked paths that differ from HEAD, each with the digest of what is on disk."""
    output = _git(root, "diff", "--name-only", "-z", "--no-renames", "HEAD", "--")
    if output is None:
        return unknown("git could not compare the working tree with HEAD")
    return [_tracked_entry(root, name) for name in _names(output)]


def _tracked_entry(root: Path, name: str) -> dict[str, Any]:
    """A modified tracked path and the digest of what is on disk. A failure to examine
    or read it costs only this entry's digest."""
    path = root / name
    entry: dict[str, Any] = {"path": name}
    try:
        if _hidden(Path(name)) or not _inside(root, path):
            entry["sha256"] = unknown("not read: a dot-path or a symbolic link")
        elif not path.exists():
            entry["deleted"] = True
        elif not path.is_file():
            entry["sha256"] = unknown("not read: not a regular file")
        else:
            entry["sha256"] = _file_digest(path)
    except _READ_ERRORS as exc:
        entry["sha256"] = _not_read(exc)
    return entry


def _untracked_code(root: Path, package_dir: Path) -> list[dict[str, Any]] | dict[str, str]:
    """Untracked paths zen could load: anything in the imported package, and importable
    packages or modules at the checkout's top, never a folder something else wrote."""
    output = _git(root, "ls-files", "--others", "--directory", "-z", "--")
    if output is None:
        return unknown("git could not list untracked paths")
    paths = [root / name.rstrip("/") for name in _names(output)]
    entries = [
        _presence(root, path)
        for path in paths
        if _loadable(root, package_dir, path) and not _generated(path)
    ]
    return [entry for entry in entries if entry is not None]


def _loadable(root: Path, package_dir: Path, path: Path) -> bool:
    """Anything inside the package; at the top, packages and modules that can be imported."""
    parts = path.relative_to(root).parts
    if parts[0] == package_dir.name:
        return len(parts) > 1
    return len(parts) == 1 and (path.suffix == ".py" or (path / "__init__.py").is_file())


def _generated(directory: Path) -> bool:
    """A folder the interpreter, a developer tool or a scan writes, never counted: a
    bytecode cache, a tool cache (CACHEDIR.TAG), a virtual environment under any name
    (pyvenv.cfg) or zen's run output. A symbolic link is judged by its own name only;
    what it points to is never looked at."""
    if directory.name in (_CACHE_DIR, RUNS_DIR_NAME):
        return True
    if directory.is_symlink():
        return False
    return any((directory / marker).is_file() for marker in _GENERATED_MARKERS)


def _files(path: Path) -> list[Path]:
    """The files of an untracked file or folder, never inside a generated folder. A
    symbolic link is one file of its own, whatever it points to, and is never walked:
    the walk lists a link inside a folder among its files and never descends into it."""
    if path.is_symlink() or not path.is_dir():
        return [path]
    found: list[Path] = []
    for directory, folders, names in path.walk():
        folders[:] = sorted(name for name in folders if not _generated(directory / name))
        found.extend(directory / name for name in names)
    return sorted(found)


def _counted(root: Path, path: Path) -> bool:
    """A dot-file counts only when it is code, a prompt template or a skill; any other
    dot-file is tool state."""
    return path.suffix in _HASHED_SUFFIXES or not _hidden(path.relative_to(root))


def _presence(root: Path, path: Path) -> dict[str, Any] | None:
    """Presence and digest of an untracked file or folder; None if nothing in it counts.
    A failure to list, size or read it costs only this entry's digest."""
    entry: dict[str, Any] = {"path": path.relative_to(root).as_posix(), "present": True}
    try:
        files = [p for p in _files(path) if _counted(root, p)]
        if not files:
            return None
        hashed = [p for p in files if _hashable(root, p)]
        entry.update(files=len(hashed), not_read=len(files) - len(hashed))
        entry["sha256"] = _entry_digest(root, hashed)
    except _READ_ERRORS as exc:
        entry["sha256"] = _not_read(exc)
    return entry


def _entry_digest(root: Path, hashed: list[Path]) -> str | dict[str, str]:
    """One digest over the files that may be hashed, unless there are none or they are
    larger than the hashing limit."""
    if not hashed:
        return unknown("not read: nothing in it may be opened and hashed")
    if sum(p.stat().st_size for p in hashed) > _MAX_HASHED_BYTES:
        return unknown("not read: larger than the hashing limit")
    return _aggregate(root, hashed)


def _hashable(root: Path, path: Path) -> bool:
    """Code, prompt templates and skills inside the checkout; never a dot-path or a link."""
    return (
        path.suffix in _HASHED_SUFFIXES
        and not _hidden(path.relative_to(root))
        and _inside(root, path)
    )


def _aggregate(root: Path, files: list[Path]) -> str:
    """One digest over each file's path and digest, in path order."""
    digest = hashlib.sha256()
    for path in files:
        line = f"{path.relative_to(root).as_posix()}\0{_file_digest(path)}\n"
        digest.update(line.encode("utf-8", "surrogateescape"))
    return digest.hexdigest()


# ── the sandbox image ────────────────────────────────────────────────────────


def _sandbox(image: str, bundle: dict[str, Any]) -> dict[str, Any]:
    """The image the sandbox container was created from, as the local daemon tells it.

    Read from the running container, so it names the image that actually ran;
    nothing is pulled and no registry is asked.
    """
    record: dict[str, Any] = {"image_ref": image}
    daemon = getattr(bundle.get("client"), "docker_client", None)
    state = getattr(getattr(bundle.get("session"), "_inner", None), "state", None)
    container_id = getattr(state, "container_id", None)
    if daemon is None or not isinstance(container_id, str) or not container_id:
        reason = "the sandbox backend exposes no Docker container to inspect"
        return {**record, "image_id": unknown(reason), "repo_digests": unknown(reason)}
    try:
        image_id = str(daemon.containers.get(container_id).attrs["Image"])
        digests = daemon.images.get(image_id).attrs.get("RepoDigests") or []
    except Exception as exc:  # noqa: BLE001 - a daemon failure is an unknown, not a failure
        reason = f"the Docker daemon did not describe the container: {type(exc).__name__}"
        return {**record, "image_id": unknown(reason), "repo_digests": unknown(reason)}
    return {**record, "image_id": image_id, "repo_digests": sorted(str(d) for d in digests)}


# ── the runtime ──────────────────────────────────────────────────────────────


def _runtime() -> dict[str, Any]:
    """Python and the libraries a turn passes through, as installed where zen runs, and
    the whole installed set as a count and one digest."""
    return {
        "python": platform.python_version(),
        "libraries": {name: _version(name) for name in _LIBRARIES},
        "installed_distributions": _value(_distributions),
        "bundled_cli_in_zen_environment": _bundled_cli_version(),
    }


def _distributions() -> dict[str, Any]:
    """Every installed distribution: how many, and one digest of their sorted
    name==version list, so a change anywhere in the environment changes the record."""
    pins = sorted(
        f"{_NAME_SEPARATORS.sub('-', str(dist.name)).lower()}=={dist.version}"
        for dist in metadata.distributions()
    )
    digest = hashlib.sha256("\n".join(pins).encode("utf-8")).hexdigest()
    return {"count": len(pins), "sha256": digest}


def _version(name: str) -> str | dict[str, str]:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return unknown(f"{name} is not installed")


def _bundled_cli_version() -> str | dict[str, str]:
    """The Claude Code CLI version claude-agent-sdk ships, read without importing it. A
    failure to read the file costs only this value."""
    try:
        files = metadata.files("claude-agent-sdk") or []
    except metadata.PackageNotFoundError:
        return unknown("claude-agent-sdk is not installed")
    found = next((file for file in files if file.as_posix() == _CLI_VERSION_FILE), None)
    if found is None:
        return unknown("claude-agent-sdk records no bundled CLI version file")
    try:
        text = found.read_text(encoding="utf-8")
    except _READ_ERRORS as exc:
        return _not_read(exc)
    match = _CLI_VERSION.search(text)
    return match.group(1) if match else unknown("the bundled CLI version file names no version")


# ── the model endpoint ───────────────────────────────────────────────────────


def _endpoint(
    provider: Any, model: str, settings: Any, fetch: Callable[[str], Any]
) -> dict[str, Any]:
    """Where model requests go, as the model provider itself resolves it. Only an
    endpoint on this machine is asked for its health reply, at that same address."""
    if codex.subscription_model(model):
        return {"kind": "subscription"}
    base_url = _base_url(provider, settings)
    if not base_url:
        return {"kind": "provider_default"}
    try:
        parts = urlsplit(base_url)
        host = parts.hostname
        address = _address(parts)
    except ValueError:
        return {"kind": unknown("the model endpoint is not a valid URL")}
    if not host:
        return {"kind": unknown("the model endpoint names no host")}
    if not _is_loopback(host):
        return {"kind": "remote", "address": address}
    return {
        "kind": "loopback",
        "address": address,
        **_health(address, fetch),
        "bridge_effort": unknown("a bridge applies its own effort and does not declare it"),
    }


def _base_url(provider: Any, settings: Any) -> str | None:
    """The base URL the model provider sends requests to: its one resolution."""
    endpoint = provider.endpoint(settings.llm)
    return str(endpoint) if endpoint else None


def _address(parts: SplitResult) -> str:
    """Scheme, host and port only: never credentials, a path or a query."""
    host = parts.hostname or ""
    shown = f"[{host}]" if ":" in host else host
    return f"{parts.scheme}://{shown}" + (f":{parts.port}" if parts.port else "")


def _is_loopback(host: str) -> bool:
    return host in _LOOPBACK_HOSTS


def _health(address: str, fetch: Callable[[str], Any]) -> dict[str, Any]:
    try:
        reply = fetch(f"{address}/health")
    except Exception as exc:  # noqa: BLE001 - an endpoint that does not answer is an unknown
        return {"health": unknown(f"the health reply could not be read: {type(exc).__name__}")}
    if not isinstance(reply, dict):
        return {"health": unknown("the health reply is not a JSON object")}
    declared = {name: reply[name] for name in _HEALTH_FIELDS if _scalar(reply.get(name))}
    return {
        "health": {
            "declared": declared,
            "other_fields": sorted(str(name) for name in reply if name not in _HEALTH_FIELDS),
        },
        "bridge_identity": unknown(
            "the health reply declares no code version, CLI version, SDK version or effort"
        ),
    }


def _scalar(value: Any) -> bool:
    return isinstance(value, str | int | float | bool)


def _fetch_health(url: str) -> Any:
    reply = httpx.get(url, timeout=_HEALTH_TIMEOUT_S, trust_env=False, follow_redirects=False)
    reply.raise_for_status()
    return reply.json()


#: How a local endpoint's health reply is read when a scan starts. A test replaces it.
DEFAULT_FETCH_HEALTH: Callable[[str], Any] = _fetch_health


# ── what governed the run ────────────────────────────────────────────────────


def _run_settings(
    provider: Any, model: str, settings: Any, given: dict[str, Any]
) -> dict[str, Any]:
    """What governed the run: the runner's resolved settings, zen's own reasoning
    effort (a bridge applies its own; see the endpoint), and the stream-idle limit as
    configured and as the provider puts it in effect."""
    llm = settings.llm
    return {
        **given,
        "zen_reasoning_effort": _value(lambda: llm.reasoning_effort),
        "prompt_cache": _value(lambda: llm.prompt_cache),
        "stream_idle_limit_s": _idle_limits(provider, model, llm),
    }


def _idle_limits(provider: Any, model: str, llm: Any) -> dict[str, Any]:
    """The configured stream-idle limit, and the one the provider's own computation applies."""
    return {
        "configured": _value(lambda: float(llm.stream_idle_timeout)),
        "in_effect": _value(lambda: provider.stream_idle_limit(model, llm)),
    }


# ── the record ───────────────────────────────────────────────────────────────


def capture_provenance(
    *,
    package_dir: Path,
    image: str,
    bundle: dict[str, Any],
    provider: Any,
    model: str,
    settings: Any,
    run_settings: dict[str, Any],
    resumed: bool,
    fetch_health: Callable[[str], Any],
) -> dict[str, Any]:
    """The provenance block of one scan start. Never raises."""
    return {
        "schema_version": PROVENANCE_SCHEMA_VERSION,
        "kind": "resume" if resumed else "start",
        "recorded_at": datetime.now(UTC).isoformat(),
        "zen": _field(_source, package_dir),
        "sandbox": _field(_sandbox, image, bundle),
        "runtime": _field(_runtime),
        "model_endpoint": _field(_endpoint, provider, model, settings, fetch_health),
        "settings": _field(_run_settings, provider, model, settings, run_settings),
    }


def write_provenance(run_dir: Path, block: dict[str, Any]) -> dict[str, Any]:
    """Create the block's own file in ``run_dir``; return what run.json keeps of it.

    The first start of a run writes ``provenance.json`` and each later start the
    next free ``provenance.<n>.json``. Each file is created exclusively and never
    rewritten, so an earlier start's record survives every later one. The file is
    ASCII: a file name that is not valid UTF-8 reaches it as an escape, never as an
    encoding failure that loses the record.
    """
    text = json.dumps(block, ensure_ascii=True, indent=2, sort_keys=True, default=str)
    payload = text.encode("utf-8")
    for index in range(1, _MAX_RECORDS + 1):
        name = PROVENANCE_FILENAME if index == 1 else f"provenance.{index}.json"
        try:
            with (run_dir / name).open(_CREATE_MODE) as handle:
                handle.write(payload)
        except FileExistsError:
            continue
        return reference_for(name, payload, block)
    raise FileExistsError(f"{_MAX_RECORDS} provenance records already exist in {run_dir}")


def _section(block: dict[str, Any], key: str) -> dict[str, Any]:
    value = block.get(key)
    return value if isinstance(value, dict) else {}


def reference_for(name: str, payload: bytes, block: dict[str, Any]) -> dict[str, Any]:
    """What run.json keeps of one record: its file, its digest and a summary in counts.

    A summary value is None where the record holds an unknown; paths and names stay
    in the record itself.
    """
    source = _section(block, "zen")
    tree = _section(source, "tree")
    modified = tree.get("modified_tracked")
    untracked = tree.get("untracked_code")
    return {
        "file": name,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "kind": block.get("kind"),
        "recorded_at": block.get("recorded_at"),
        "zen_commit": _known(source.get("commit")),
        "modified_tracked_files": len(modified) if isinstance(modified, list) else None,
        "untracked_code_paths": len(untracked) if isinstance(untracked, list) else None,
        "image_id": _known(_section(block, "sandbox").get("image_id")),
    }


async def _capture_and_write(
    run_dir: Path,
    *,
    resumed: bool,
    image: str,
    bundle: dict[str, Any],
    provider: Any,
    model: str,
    settings: Any,
    run_settings: dict[str, Any],
    package_dir: Path | None = None,
    fetch_health: Callable[[str], Any] | None = None,
) -> dict[str, Any]:
    """Capture the block off the event loop (it runs git and asks the Docker daemon),
    then write it. A ``package_dir`` or ``fetch_health`` not passed is read now from
    :data:`DEFAULT_PACKAGE_DIR` or :data:`DEFAULT_FETCH_HEALTH`. Either step may
    raise; :func:`record_run_provenance` guards both."""
    block = await asyncio.to_thread(
        capture_provenance,
        package_dir=DEFAULT_PACKAGE_DIR if package_dir is None else package_dir,
        image=image,
        bundle=bundle,
        provider=provider,
        model=model,
        settings=settings,
        run_settings=run_settings,
        resumed=resumed,
        fetch_health=DEFAULT_FETCH_HEALTH if fetch_health is None else fetch_health,
    )
    return write_provenance(run_dir, block)


def _attach(scan_id: str, reference: dict[str, Any]) -> None:
    """Name the record in run.json when the run's report state is this scan's."""
    report_state = get_global_report_state()
    if report_state is not None and (report_state.run_name or report_state.run_id) == scan_id:
        report_state.record_provenance(reference)


async def record_run_provenance(
    run_dir: Path,
    *,
    scan_id: str,
    resumed: bool,
    image: str,
    bundle: dict[str, Any],
    provider: Any,
    model: str,
    settings: Any,
    run_settings: dict[str, Any],
    package_dir: Path | None = None,
    fetch_health: Callable[[str], Any] | None = None,
) -> dict[str, Any] | None:
    """Record this start's provenance before any agent runs. Never raises.

    A ``package_dir`` or ``fetch_health`` not passed is read at call time from
    :data:`DEFAULT_PACKAGE_DIR` (the imported zen package) or
    :data:`DEFAULT_FETCH_HEALTH` (the real health request); a test points those
    defaults at a throwaway checkout and a stand-in. A failure is one warning line
    naming its cause, and the scan goes on with nothing named in run.json.
    """
    try:
        reference = await _capture_and_write(
            run_dir,
            resumed=resumed,
            image=image,
            bundle=bundle,
            provider=provider,
            model=model,
            settings=settings,
            run_settings=run_settings,
            package_dir=package_dir,
            fetch_health=fetch_health,
        )
        _attach(scan_id, reference)
    except Exception as exc:  # noqa: BLE001 - provenance never fails a scan
        logger.warning(
            "run provenance was not recorded (%s: %s); the scan continues without it",
            type(exc).__name__,
            exc,
        )
        return None
    logger.info(
        "run provenance recorded in %s (commit %s, image %s)",
        reference["file"],
        reference["zen_commit"],
        reference["image_id"],
    )
    return reference
