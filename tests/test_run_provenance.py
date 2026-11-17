"""Run provenance: what produced a run, recorded once at scan start.

Every capture here runs against a throwaway git checkout under ``tmp_path`` that
holds a synthetic package, never against the developer's own tree. The Docker
daemon, the model provider and every health reply are stand-ins; hosts are
reserved names (``*.example.test``) or loopback addresses nothing is asked on.
The scan-level tests point provenance's module-level defaults at the throwaway
checkout and a stand-in health reply and pin the bridge turn bound, so no
endpoint is probed; they never replace the runner's own reference.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import logging
import os
import platform
import shutil
import subprocess
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, override

import httpx
import pytest
from agents.models.interface import Model
from openai import AsyncOpenAI

import zen
from tests.test_runner_teardown import _wire_runner
from zen.config import codex, loader, models
from zen.config.loader import load_settings
from zen.config.models import ZenProvider, _TurnGuardModel
from zen.config.settings import LlmSettings
from zen.core import provenance, runner
from zen.core.agents import AgentCoordinator
from zen.core.paths import RUNS_DIR_NAME
from zen.report import state as report_state_module
from zen.report.coverage import build_coverage_document
from zen.report.state import ReportState
from zen.report.writer import write_executive_report


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


_GIT = shutil.which("git")
_SCAN = "scan-provenance"
_PLANTED = "SYNTHETIC-PLANTED-VALUE"
_CONTENT = "SYNTHETIC-CONTENT-MARKER"
_IMAGE = "registry.example.test/sandbox:1"
_LOCAL = "http://127.0.0.1:8787/v1"
_HEALTHY = {"status": "ok", "turn_timeout_s": 1800.0}
_CACHE_TAG = "Signature: 8a477f597d28d172789f06886806bc55\n"
_FAILURES = {
    "capture": RuntimeError("synthetic capture failure"),
    "write": OSError("synthetic write failure"),
}


def _git(cwd: Path, *args: str) -> None:
    identity = ("-c", "user.name=t", "-c", "user.email=t@example.test")
    subprocess.run(  # noqa: S603
        [str(_GIT), *identity, "-c", "commit.gpgsign=false", *args],
        cwd=cwd,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
        check=True,
        capture_output=True,
    )


def _head(cwd: Path) -> str:
    done = subprocess.run(  # noqa: S603
        [str(_GIT), "rev-parse", "HEAD"], cwd=cwd, capture_output=True, text=True, check=True
    )
    return done.stdout.strip()


@pytest.fixture
def package(tmp_path: Path) -> Path:
    """A synthetic package at the top of a committed throwaway checkout."""
    if _GIT is None:
        pytest.skip("git is needed to build a throwaway checkout")
    package_dir = tmp_path / "checkout" / "pkg"
    package_dir.mkdir(parents=True)
    (package_dir / "__init__.py").write_text("", encoding="utf-8")
    (package_dir / "module.py").write_text("VALUE = 1\n", encoding="utf-8")
    for args in (("init", "--quiet"), ("add", "--all"), ("commit", "--quiet", "-m", "init")):
        _git(package_dir.parent, *args)
    return package_dir


class _Lines(logging.Handler):
    """Keeps every record one logger emits."""

    def __init__(self) -> None:
        super().__init__(logging.DEBUG)
        self.records: list[logging.LogRecord] = []

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


@pytest.fixture
def provenance_log() -> Iterator[_Lines]:
    """What zen.core.provenance logs, read off that logger itself: an earlier test can
    leave zen's loggers detached from the root logger that caplog listens on."""
    logger = logging.getLogger(provenance.__name__)
    handler = _Lines()
    level = logger.level
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    try:
        yield handler
    finally:
        logger.removeHandler(handler)
        logger.setLevel(level)


class _UnusedModel(Model):
    """A model that get_model wraps and nothing calls."""

    @override
    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    @override
    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def _settings(api_base: str | None = None) -> Any:
    llm = types.SimpleNamespace(
        api_base=api_base,
        reasoning_effort="high",
        prompt_cache=True,
        stream_idle_timeout=300,
    )
    return types.SimpleNamespace(llm=llm)


def _provider(endpoint: str | None = None, in_effect: float = 300.0) -> Any:
    """A stand-in for the model provider's own resolution."""
    return types.SimpleNamespace(
        endpoint=lambda _llm: endpoint,
        stream_idle_limit=lambda _model, _llm: in_effect,
    )


def _healthy(_url: str) -> Any:
    return dict(_HEALTHY)


def _capture(package_dir: Path, **overrides: Any) -> dict[str, Any]:
    arguments: dict[str, Any] = {
        "package_dir": package_dir,
        "image": _IMAGE,
        "bundle": {"client": None, "session": None},
        "provider": _provider(),
        "model": "provider/model-a",
        "settings": _settings(),
        "run_settings": {"model": "provider/model-a", "scan_mode": "quick", "max_turns": 7},
        "resumed": False,
        "fetch_health": _healthy,
    }
    return provenance.capture_provenance(**{**arguments, **overrides})


def _scan_settings() -> Any:
    """Settings for a scan start whose model endpoint is a local bridge."""
    llm = types.SimpleNamespace(
        model="openai/gpt-4o",
        api_base=_LOCAL,
        reasoning_effort="high",
        force_required_tool_choice=False,
        timeout=300,
        prompt_cache=True,
        extra_headers=None,
        stream_idle_timeout=300,
        disable_streaming=False,
    )
    return types.SimpleNamespace(llm=llm, runtime=types.SimpleNamespace(max_context_images=3))


def _hermetic_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, package_dir: Path
) -> tuple[Path, ReportState, list[bool]]:
    """Wire a scan start whose provenance reads only the throwaway checkout and the
    stand-in health reply, and whose root agent notes whether a record existed. Only
    provenance's module-level defaults are pointed elsewhere; the runner keeps its own
    reference to record_run_provenance."""
    run_dir = tmp_path / "zen_runs" / _SCAN
    monkeypatch.chdir(tmp_path)
    _wire_runner(monkeypatch, run_dir)
    monkeypatch.setattr(runner, "load_settings", _scan_settings)
    monkeypatch.setattr(models, "_bridge_turn_bound", lambda _base_url: 1800.0)
    monkeypatch.setattr(provenance, "DEFAULT_PACKAGE_DIR", package_dir)
    monkeypatch.setattr(provenance, "DEFAULT_FETCH_HEALTH", _healthy)
    state = ReportState(_SCAN)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    seen: list[bool] = []

    async def _root(**_kwargs: Any) -> None:
        seen.append((run_dir / "provenance.json").is_file())

    monkeypatch.setattr(runner, "run_agent_loop", _root)
    return run_dir, state, seen


async def _start_scan() -> None:
    await runner.run_zen_scan(
        scan_config={"targets": [], "scan_mode": "quick"},
        scan_id=_SCAN,
        image=_IMAGE,
        coordinator=AgentCoordinator(),
    )


def _write_generated(package_dir: Path) -> None:
    """What the interpreter, developer tools and a scan leave in a checkout. None of it
    may change the record: outside the package nothing but importable code counts, and
    inside it a bytecode cache, a tool cache, a virtual environment and run output are
    the folders that never count."""
    root = package_dir.parent
    bytecode = package_dir / "__pycache__"
    bytecode.mkdir()
    (bytecode / "module.cpython-314.pyc").write_bytes(b"synthetic bytecode")
    output = root / "results" / "run-1"
    output.mkdir(parents=True)
    (output / "report.md").write_text("# Synthetic report\n", encoding="utf-8")
    (output / "summary.json").write_text("{}\n", encoding="utf-8")
    for cache in (root / ".tool_cache", package_dir / ".tool_cache"):
        cache.mkdir()
        (cache / "CACHEDIR.TAG").write_text(_CACHE_TAG, encoding="utf-8")
        (cache / "README.md").write_text("# Synthetic cache\n", encoding="utf-8")
    environment = package_dir / "env"
    (environment / "lib").mkdir(parents=True)
    (environment / "pyvenv.cfg").write_text("home = /usr/bin\n", encoding="utf-8")
    (environment / "lib" / "site.py").write_text("VALUE = 2\n", encoding="utf-8")
    run_output = package_dir / RUNS_DIR_NAME / "run-1"
    run_output.mkdir(parents=True)
    (run_output / "penetration_test_report.md").write_text("# Synthetic\n", encoding="utf-8")


def test_two_captures_of_one_tree_differ_only_in_their_time(package: Path) -> None:
    first = _capture(package)
    _write_generated(package)
    second = _capture(package)

    assert first.pop("recorded_at")
    assert second.pop("recorded_at")
    assert first == second
    assert first["zen"]["commit_from"] == "git checkout"
    assert len(first["zen"]["commit"]) == 40
    tree = first["zen"]["tree"]
    assert tree == {"modified": False, "modified_tracked": [], "untracked_code": []}


def test_a_modified_tracked_file_changes_the_record(package: Path) -> None:
    before = _capture(package)
    changed = package / "module.py"
    changed.write_text("VALUE = 22\n", encoding="utf-8")

    after = _capture(package)

    digest = hashlib.sha256(changed.read_bytes()).hexdigest()
    assert before["zen"]["tree"]["modified"] is False
    assert after["zen"]["tree"]["modified"] is True
    assert after["zen"]["tree"]["modified_tracked"] == [{"path": "pkg/module.py", "sha256": digest}]
    assert after["zen"]["commit"] == before["zen"]["commit"]


def test_untracked_code_alone_makes_the_tree_modified(package: Path) -> None:
    (package / "added.py").write_text("VALUE = 3\n", encoding="utf-8")

    tree = _capture(package)["zen"]["tree"]

    assert tree["modified_tracked"] == []
    assert [entry["path"] for entry in tree["untracked_code"]] == ["pkg/added.py"]
    assert tree["modified"] is True


@pytest.mark.parametrize(
    ("failing", "unlisted", "empty"),
    [
        pytest.param("ls-files", "untracked_code", "modified_tracked", id="untracked-unlisted"),
        pytest.param("diff", "modified_tracked", "untracked_code", id="tracked-uncompared"),
    ],
)
def test_a_list_git_cannot_produce_leaves_the_tree_modified_unknown(
    failing: str, unlisted: str, empty: str, package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """One list is known and empty, the other could not be produced: nothing shows the
    tree clean, so whether it is modified is unknown, never false."""
    real_git = provenance._git

    def _refusing(root: Path, *args: str) -> str | None:
        return None if args[0] == failing else real_git(root, *args)

    monkeypatch.setattr(provenance, "_git", _refusing)

    source = _capture(package)["zen"]

    assert source["commit"] == _head(package.parent)
    tree = source["tree"]
    assert tree[empty] == []
    assert set(tree[unlisted]) == {"unknown"}
    modified = tree["modified"]
    assert isinstance(modified, dict)
    assert set(modified) == {"unknown"}
    assert modified["unknown"]


def test_untracked_code_is_recorded_by_presence_and_digest_never_content(
    package: Path, tmp_path: Path
) -> None:
    root = package.parent
    harness = root / "harness"
    harness.mkdir()
    (harness / "__init__.py").write_text("", encoding="utf-8")
    (harness / "runner.py").write_text(f"MARK = {_CONTENT!r}\n", encoding="utf-8")
    outside = tmp_path / "outside.py"
    outside.write_text(f"KEY = {_PLANTED!r}\n", encoding="utf-8")
    (harness / "linked.py").symlink_to(outside)
    (package / "extra.md").write_text(_CONTENT, encoding="utf-8")
    (package / ".local_settings.py").write_text(f"KEY = {_PLANTED!r}\n", encoding="utf-8")
    (root / "notes.txt").write_text(_CONTENT, encoding="utf-8")

    block = _capture(package)
    (harness / "runner.py").write_text("MARK = 'changed'\n", encoding="utf-8")
    changed = _capture(package)

    entries = {entry["path"]: entry for entry in block["zen"]["tree"]["untracked_code"]}
    later = {entry["path"]: entry for entry in changed["zen"]["tree"]["untracked_code"]}
    assert sorted(entries) == ["harness", "pkg/.local_settings.py", "pkg/extra.md"]
    found = entries["harness"]
    assert (found["present"], found["files"], found["not_read"]) == (True, 2, 1)
    hidden = entries["pkg/.local_settings.py"]
    assert (hidden["files"], hidden["not_read"]) == (0, 1)
    assert "unknown" in hidden["sha256"]
    assert later["harness"]["sha256"] != found["sha256"]
    recorded = json.dumps([block, changed])
    assert _CONTENT not in recorded
    assert _PLANTED not in recorded


def test_an_untracked_link_to_a_folder_is_one_entry_and_is_never_walked(
    package: Path, tmp_path: Path
) -> None:
    """The folder the link points to lies outside the checkout and holds a tool-cache
    marker: a link is judged by its own name, never by what it points to."""
    target = tmp_path / "elsewhere"
    (target / "nested").mkdir(parents=True)
    (target / "CACHEDIR.TAG").write_text(_CACHE_TAG, encoding="utf-8")
    (target / "module.py").write_text(f"KEY = {_PLANTED!r}\n", encoding="utf-8")
    (target / "nested" / "notes.md").write_text(_CONTENT, encoding="utf-8")
    (package / "linked").symlink_to(target, target_is_directory=True)

    block = _capture(package)

    entries = block["zen"]["tree"]["untracked_code"]
    assert [entry["path"] for entry in entries] == ["pkg/linked"]
    (linked,) = entries
    assert (linked["present"], linked["files"], linked["not_read"]) == (True, 0, 1)
    assert set(linked["sha256"]) == {"unknown"}
    recorded = json.dumps(block)
    assert _PLANTED not in recorded
    assert _CONTENT not in recorded


def test_a_failed_read_costs_only_that_files_digest(
    package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("__init__.py", "module.py", "added.py", "other.py"):
        (package / name).write_text("VALUE = 5\n", encoding="utf-8")
    failures: dict[Path, OSError] = {
        package / "module.py": PermissionError("synthetic read failure"),
        package / "added.py": FileNotFoundError("synthetic read failure"),
    }
    real_digest = provenance._file_digest

    def _digest(path: Path) -> str:
        if path in failures:
            raise failures[path]
        return real_digest(path)

    monkeypatch.setattr(provenance, "_file_digest", _digest)

    source = _capture(package)["zen"]

    assert source["commit"] == _head(package.parent)
    tree = source["tree"]
    digests = {
        entry["path"]: entry["sha256"]
        for entry in [*tree["modified_tracked"], *tree["untracked_code"]]
    }
    assert sorted(digests) == ["pkg/__init__.py", "pkg/added.py", "pkg/module.py", "pkg/other.py"]
    unread = {path: value for path, value in digests.items() if isinstance(value, dict)}
    assert sorted(unread) == ["pkg/added.py", "pkg/module.py"]
    assert "PermissionError" in unread["pkg/module.py"]["unknown"]
    assert "FileNotFoundError" in unread["pkg/added.py"]["unknown"]


def test_a_failed_read_of_the_bundled_cli_version_costs_only_that_value(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _refused(**_options: Any) -> str:
        raise PermissionError("synthetic read failure")

    listed = types.SimpleNamespace(
        as_posix=lambda: provenance._CLI_VERSION_FILE, read_text=_refused
    )
    monkeypatch.setattr(provenance.metadata, "files", lambda _name: [listed])

    runtime = _capture(tmp_path / "pkg")["runtime"]

    cli = runtime["bundled_cli_in_zen_environment"]
    assert set(cli) == {"unknown"}
    assert "PermissionError" in cli["unknown"]
    assert runtime["python"] == platform.python_version()
    assert sorted(runtime["libraries"]) == sorted(provenance._LIBRARIES)


class _UnreadableSettings:
    """Settings whose model section cannot be read."""

    @property
    def llm(self) -> Any:
        raise RuntimeError("the settings could not be read")


def test_a_value_that_cannot_be_determined_is_recorded_as_unknown_with_a_reason(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(provenance, "_installed_commit", lambda: None)
    loose = tmp_path / "loose" / "pkg"
    loose.mkdir(parents=True)

    def _daemon_refuses(_container_id: str) -> Any:
        raise ConnectionError("the daemon is not answering")

    daemon = types.SimpleNamespace(containers=types.SimpleNamespace(get=_daemon_refuses))
    state = types.SimpleNamespace(container_id="0123abcd")
    session = types.SimpleNamespace(_inner=types.SimpleNamespace(state=state))

    block = _capture(
        loose,
        bundle={"client": types.SimpleNamespace(docker_client=daemon), "session": session},
        settings=_UnreadableSettings(),
    )

    unknowns = [
        block["zen"]["commit"],
        block["zen"]["tree"],
        block["sandbox"]["image_id"],
        block["sandbox"]["repo_digests"],
        block["model_endpoint"],
        block["settings"],
    ]
    assert all(set(value) == {"unknown"} and value["unknown"] for value in unknowns)
    assert block["sandbox"]["image_ref"] == _IMAGE


def test_the_endpoint_is_the_providers_and_only_a_loopback_one_is_asked_for_its_health(
    package: Path,
) -> None:
    asked: list[str] = []

    def _reply(url: str) -> Any:
        asked.append(url)
        return {**_HEALTHY, "error": _PLANTED}

    def _refused(_url: str) -> Any:
        raise OSError("connection refused")

    configured = _settings("https://configured.example.test/v1")
    local = _capture(package, provider=_provider(_LOCAL), settings=configured, fetch_health=_reply)
    remote_url = f"https://user:{_PLANTED}@api.example.test:8443/v1?key={_PLANTED}"
    remote = _capture(package, provider=_provider(remote_url), fetch_health=_reply)
    silent = _capture(package, provider=_provider("http://localhost:9/v1"), fetch_health=_refused)

    assert asked == ["http://127.0.0.1:8787/health"]
    endpoint = local["model_endpoint"]
    assert (endpoint["kind"], endpoint["address"]) == ("loopback", "http://127.0.0.1:8787")
    assert endpoint["health"] == {"declared": _HEALTHY, "other_fields": ["error"]}
    assert endpoint["bridge_identity"]["unknown"]
    assert endpoint["bridge_effort"]["unknown"]
    expected_remote = {"kind": "remote", "address": "https://api.example.test:8443"}
    assert remote["model_endpoint"] == expected_remote
    assert silent["model_endpoint"]["health"]["unknown"]
    assert _PLANTED not in json.dumps([local, remote, silent])


def test_every_git_call_switches_off_the_file_system_monitor(
    package: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    commands: list[list[str]] = []
    real_run = subprocess.run

    def _recording(command: list[str], **kwargs: Any) -> Any:
        commands.append(list(command))
        return real_run(command, **kwargs)

    monkeypatch.setattr(provenance.subprocess, "run", _recording)
    _capture(package)

    assert len(commands) >= 4
    for command in commands:
        options = command[: command.index("-C")]
        assert options[0] == "git"
        assert ("-c", "core.fsmonitor=false") in itertools.pairwise(options)


def test_git_environment_variables_cannot_point_the_reads_at_another_repository(
    package: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "other.txt").write_text("another repository\n", encoding="utf-8")
    for args in (("init", "--quiet"), ("add", "--all"), ("commit", "--quiet", "-m", "other")):
        _git(elsewhere, *args)
    own = _head(package.parent)
    assert _head(elsewhere) != own
    monkeypatch.setenv("GIT_DIR", str(elsewhere / ".git"))

    block = _capture(package)

    assert block["zen"]["commit"] == own
    assert block["zen"]["tree"]["modified"] is False


def test_each_start_writes_its_own_file_and_never_rewrites_an_earlier_one(
    tmp_path: Path,
) -> None:
    first = provenance.write_provenance(
        tmp_path, {"kind": "start", "recorded_at": "t1", "zen": {"commit": "a" * 40}}
    )
    kept = (tmp_path / "provenance.json").read_bytes()
    second = provenance.write_provenance(
        tmp_path, {"kind": "resume", "recorded_at": "t2", "zen": {"commit": "b" * 40}}
    )

    assert (first["file"], second["file"]) == ("provenance.json", "provenance.2.json")
    assert (tmp_path / "provenance.json").read_bytes() == kept
    for reference in (first, second):
        written = (tmp_path / reference["file"]).read_bytes()
        assert reference["sha256"] == hashlib.sha256(written).hexdigest()
    assert (second["kind"], second["zen_commit"]) == ("resume", "b" * 40)


def test_a_file_name_that_is_not_valid_utf8_is_kept_in_the_written_record(
    package: Path, tmp_path: Path
) -> None:
    raw = b"module_\xff.py"
    try:
        (package / os.fsdecode(raw)).write_text("VALUE = 4\n", encoding="utf-8")
    except (OSError, UnicodeError):
        pytest.skip("this file system cannot hold a name that is not valid UTF-8")
    run_dir = tmp_path / "run"
    run_dir.mkdir()

    reference = provenance.write_provenance(run_dir, _capture(package))

    written = json.loads((run_dir / reference["file"]).read_text(encoding="utf-8"))
    listed = [entry["path"] for entry in written["zen"]["tree"]["untracked_code"]]
    assert listed == ["pkg/" + raw.decode("utf-8", "surrogateescape")]


@pytest.mark.asyncio
async def test_the_runner_records_provenance_before_any_agent_runs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, package: Path
) -> None:
    run_dir, _state, seen = _hermetic_scan(monkeypatch, tmp_path, package)

    await _start_scan()

    assert seen == [True]
    block = json.loads((run_dir / "provenance.json").read_text(encoding="utf-8"))
    assert (block["kind"], block["zen"]["commit"]) == ("start", _head(package.parent))
    assert block["zen"]["commit_from"] == "git checkout"
    assert block["sandbox"]["image_ref"] == _IMAGE
    endpoint = block["model_endpoint"]
    assert (endpoint["kind"], endpoint["health"]["declared"]) == ("loopback", _HEALTHY)
    governed = block["settings"]
    assert governed["stream_idle_limit_s"] == {"configured": 300.0, "in_effect": 1860.0}
    assert (governed["zen_reasoning_effort"], governed["scan_mode"]) == ("high", "quick")
    record = json.loads((run_dir / "run.json").read_text(encoding="utf-8"))
    assert [reference["file"] for reference in record["provenance"]] == ["provenance.json"]


@pytest.mark.asyncio
@pytest.mark.parametrize("failing", sorted(_FAILURES))
async def test_a_failed_capture_or_write_never_stops_the_scan(
    failing: str,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    package: Path,
    provenance_log: _Lines,
) -> None:
    run_dir, state, seen = _hermetic_scan(monkeypatch, tmp_path, package)

    def _fails(*_args: Any, **_kwargs: Any) -> Any:
        raise _FAILURES[failing]

    monkeypatch.setattr(provenance, f"{failing}_provenance", _fails)

    await _start_scan()

    assert seen == [False]
    assert "provenance" not in state.run_record
    run_json = run_dir / "run.json"
    assert not run_json.exists() or "provenance" not in json.loads(run_json.read_text("utf-8"))
    warnings = [record for record in provenance_log.records if record.levelno == logging.WARNING]
    assert len(warnings) == 1
    message = warnings[0].getMessage()
    assert "run provenance was not recorded" in message
    assert type(_FAILURES[failing]).__name__ in message


def test_the_report_header_states_each_start_and_its_local_changes_as_counts(
    tmp_path: Path,
) -> None:
    clean = {
        "file": "provenance.json",
        "kind": "start",
        "zen_commit": "a" * 40,
        "modified_tracked_files": 0,
        "untracked_code_paths": 0,
    }
    changed = {
        "file": "provenance.2.json",
        "kind": "resume",
        "zen_commit": "b" * 40,
        "modified_tracked_files": 2,
        "untracked_code_paths": 1,
    }
    unread = {"file": "provenance.3.json", "kind": "resume", "zen_commit": None}

    write_executive_report(tmp_path, "Summary.", provenance=[clean, changed, unread])

    report = (tmp_path / "penetration_test_report.md").read_text(encoding="utf-8")
    sources = [line for line in report.splitlines() if line.startswith("**Source")]
    assert sources == [
        "**Source:** zen at commit aaaaaaaaaaaa, no local changes.",
        (
            "**Source (resumed run):** zen at commit bbbbbbbbbbbb, started with local changes: "
            "2 modified tracked file(s), 1 untracked code path(s)."
        ),
        "**Source (resumed run):** zen at an unknown commit, local changes unknown.",
    ]


def test_the_coverage_export_names_the_runs_provenance() -> None:
    reference = {"file": "provenance.json", "sha256": "0" * 64, "kind": "start"}

    document = build_coverage_document(
        run_record={"run_id": "run-1", "provenance": [reference]},
        entries=[],
        agent_graph={},
        vulnerability_reports=[],
    )

    assert document["provenance"] == [reference]


def test_the_provider_resolves_one_endpoint_for_its_requests_and_for_the_record() -> None:
    llm = LlmSettings.model_construct(api_base="https://configured.example.test/v1")
    override = "https://override.example.test/v1"

    assert ZenProvider().endpoint(llm) == "https://configured.example.test/v1"
    assert ZenProvider(base_url=override).endpoint(llm) == override


@pytest.mark.parametrize(
    ("model_name", "disable_streaming", "expected"),
    [
        pytest.param("chatgpt/gpt-5.4", "false", 45.0, id="subscription-streamed"),
        pytest.param("chatgpt/gpt-5.4", "true", 45.0, id="subscription-unstreamed"),
        pytest.param("openai/gpt-4o-mini", "false", 1860.0, id="routed-streamed"),
        pytest.param("openai/gpt-4o-mini", "true", 0.0, id="routed-unstreamed"),
    ],
)
def test_the_idle_limit_get_model_applies_is_unchanged_and_is_the_one_recorded(
    model_name: str,
    disable_streaming: str,
    expected: float,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """``expected`` is what get_model applied at fe2fba3, before the computation had a
    method of its own: the configured limit for a subscription model, the bridge's
    turn bound plus its margin for a streamed model the bridge serves, and none
    without streaming. Provenance must record exactly the value get_model applies."""
    monkeypatch.delenv("ZEN_LLM", raising=False)
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    monkeypatch.setenv("LLM_DISABLE_STREAMING", disable_streaming)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    monkeypatch.setattr(
        models, "_bridge_turn_bound", lambda base_url: 1800.0 if base_url == _LOCAL else None
    )
    monkeypatch.setattr(models.MultiProvider, "get_model", lambda *_args: _UnusedModel())
    monkeypatch.setattr(
        codex, "get_subscription_client", lambda: AsyncOpenAI(api_key="synthetic", base_url=_LOCAL)
    )
    settings = load_settings()
    provider = ZenProvider(base_url=_LOCAL)

    applied = provider.get_model(model_name)
    block = _capture(tmp_path / "pkg", provider=provider, model=model_name, settings=settings)

    assert isinstance(applied, _TurnGuardModel)
    in_effect = applied._stream_idle_timeout
    assert in_effect == expected
    recorded = block["settings"]["stream_idle_limit_s"]
    assert recorded == {"configured": 45.0, "in_effect": in_effect}


@pytest.mark.usefixtures("production_provenance_defaults")
def test_a_scan_reads_the_running_package_and_asks_with_the_modules_own_fetch() -> None:
    assert Path(zen.__file__).resolve().parent == provenance.DEFAULT_PACKAGE_DIR
    assert provenance.DEFAULT_FETCH_HEALTH is provenance._fetch_health


@pytest.mark.parametrize(
    ("status", "body", "declared"),
    [
        pytest.param(200, b'{"status": "ok", "turn_timeout_s": 1800.0}', _HEALTHY, id="answered"),
        pytest.param(503, b'{"status": "ok", "turn_timeout_s": 1800.0}', None, id="refused"),
        pytest.param(200, b"<html>not json</html>", None, id="not-json"),
        pytest.param(200, b'["status", "ok"]', None, id="not-an-object"),
    ],
)
def test_the_health_request_asks_only_the_recorded_address_and_keeps_only_an_answer(
    status: int,
    body: bytes,
    declared: dict[str, Any] | None,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls: list[tuple[str, dict[str, Any]]] = []

    def _get(url: str, **options: Any) -> httpx.Response:
        calls.append((url, options))
        return httpx.Response(status, content=body, request=httpx.Request("GET", url))

    monkeypatch.setattr(provenance.httpx, "get", _get)

    block = _capture(
        tmp_path / "pkg", provider=_provider(_LOCAL), fetch_health=provenance._fetch_health
    )

    assert [url for url, _options in calls] == ["http://127.0.0.1:8787/health"]
    options = calls[0][1]
    assert (options["trust_env"], options["follow_redirects"]) == (False, False)
    assert 0 < options["timeout"] <= provenance._HEALTH_TIMEOUT_S
    health = block["model_endpoint"]["health"]
    if declared is None:
        assert set(health) == {"unknown"}
        assert health["unknown"]
    else:
        assert health == {"declared": declared, "other_fields": []}


def test_two_clones_of_one_commit_at_different_locations_record_the_same_source(
    package: Path, tmp_path: Path
) -> None:
    captures: list[dict[str, Any]] = []
    for location in ("near", "far/away"):
        clone = tmp_path / location / "checkout"
        clone.parent.mkdir(parents=True)
        _git(tmp_path, "clone", "--quiet", str(package.parent), str(clone))
        captures.append(_capture(clone / package.name))
    first, second = captures

    assert first.pop("recorded_at")
    assert second.pop("recorded_at")
    assert first == second
    assert first["zen"]["commit"] == _head(package.parent)


def test_a_change_to_any_installed_distribution_changes_the_record(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _environment(version: str) -> Callable[[], list[Any]]:
        def _distributions() -> list[Any]:
            return [
                types.SimpleNamespace(name="Synthetic_Dependency", version=version),
                types.SimpleNamespace(name="litellm", version="1.0.0"),
            ]

        return _distributions

    monkeypatch.setattr(provenance.metadata, "distributions", _environment("1.0"))
    before = _capture(tmp_path / "pkg")
    monkeypatch.setattr(provenance.metadata, "distributions", _environment("1.1"))
    after = _capture(tmp_path / "pkg")

    assert before.pop("recorded_at")
    assert after.pop("recorded_at")
    old = before["runtime"].pop("installed_distributions")
    new = after["runtime"].pop("installed_distributions")
    assert (old["count"], new["count"]) == (2, 2)
    assert old["sha256"] != new["sha256"]
    assert before == after
