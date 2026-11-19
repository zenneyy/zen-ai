"""Stop means stop: when a scan stops, its sandbox loses its network before anything else.

The Docker client, the sandbox and the owner's host identity are stand-ins: no Docker
daemon is contacted, and every file a test writes lands in its own temporary directory.
Where a test runs main(), everything around the scan is a stand-in too.
"""

from __future__ import annotations

import asyncio
import contextlib
import importlib
import json
import logging
import os
import signal
import threading
import time
import types
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn, override

import httpx
import pytest
from agents.run_context import RunContextWrapper
from agents.sandbox.manifest import Manifest
from agents.tool import CustomTool, FunctionTool
from agents.tool_context import ToolContext
from openai import RateLimitError
from openai.types.responses import ResponseFunctionToolCall

from tests.test_go_tui_runtime import args as tui_args
from tests.test_runner_teardown import _wire_runner
from tests.test_session_entries import (
    _Client,
    _forget_backend,
    _no_caido,
    _RuntimeSettings,
    _Session,
    _Settings,
    _use_backend,
)
from zen.agents import factory
from zen.core import execution, runner
from zen.core.agents import AgentCoordinator
from zen.core.hooks import BudgetExceededError
from zen.interface import cli
from zen.interface.tui import runtime as go_tui
from zen.interface.tui.backend import TuiBackendServer
from zen.interface.tui.runtime import GoTuiRuntime
from zen.report import state as report_state_module
from zen.report.state import ReportState
from zen.runtime import backends, docker_client, owner, session_manager
from zen.runtime import stop as stop_module


if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable, Iterator


# The module itself: zen.interface re-exports main(), so the package's ``main`` is the
# function, whichever way it is imported.
main_module = importlib.import_module("zen.interface.main")

_IMAGE = "registry.example.test/sandbox:1"
_STOP_SIGNALS = [
    getattr(signal, name) for name in ("SIGINT", "SIGTERM", "SIGHUP") if hasattr(signal, name)
]
_REPORT = "# Executive Summary\n\nSummary."
_KILLED = "cut by killing the sandbox (the disconnect failed: CutError: still attached to bridge)"
_UNREACHABLE = "ConnectionError: daemon unreachable"
_SWEPT_MESSAGE = (
    "Removed 2 sandbox(es) left by a zen process that has exited (1 running, 1 stopped); "
    "each lost its network before it was removed"
)
_REMOVED_AT_EXIT = (
    "Removed 1 sandbox(es) of this zen process that were still present at exit "
    "(0 running, 1 stopped); each lost its network before it was removed"
)
_LEFT_AT_EXIT = (
    "Sandbox sandbox-1 (created) of this zen process was still present at exit: cut and removed"
)
_NOT_ARMED = "not cut (no sandbox network was armed)"
# Two daemons a Docker connection can name, so a test can tell which connection a client
# was made from.
_DAEMON_A = "tcp://daemon-a.example.test:2376"
_DAEMON_B = "tcp://daemon-b.example.test:2376"
# The states the daemon lists without all=True: those whose processes can still run.
_UP_STATES = ("running", "paused", "restarting")
# This machine as the owner labels see it. Both pids lie above the largest pid Linux can
# hand out, so neither is ever this test's own process.
_HOST = "boot-0001/pid:[4026531836]"
_OTHER_HOST = "boot-0002/pid:[4026531836]"
_USER = "1000"
_STARTED = "424242"
_ALIVE_PID = "4194401"
_DEAD_PID = "4194402"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch: pytest.MonkeyPatch) -> None:
    """No stop, no run report and no sandbox this process created carries over from
    another test."""
    monkeypatch.setattr(stop_module, "_STOPS", {})
    monkeypatch.setattr(report_state_module, "_global_report_state", None)
    monkeypatch.setattr(docker_client, "_SANDBOX_CREATED", threading.Event())


@pytest.fixture
def this_machine(monkeypatch: pytest.MonkeyPatch) -> None:
    """This test's process and one other zen process are alive here; no other is."""
    started = {os.getpid(): _STARTED, int(_ALIVE_PID): _STARTED}
    monkeypatch.setattr(owner, "host_identity", lambda: _HOST)
    monkeypatch.setattr(owner, "user_identity", lambda: _USER)
    monkeypatch.setattr(owner, "process_started", started.get)
    monkeypatch.setattr(owner, "_no_such_process", lambda pid: pid not in started)


@pytest.fixture
def stop_signal_handlers_restored() -> Iterator[None]:
    """Whatever a test binds to SIGINT, SIGTERM and SIGHUP is unbound after it."""
    saved = {signum: signal.getsignal(signum) for signum in _STOP_SIGNALS}
    try:
        yield
    finally:
        for signum, handler in saved.items():
            if handler is not None:
                signal.signal(signum, handler)


@pytest.fixture
def stop_signals_held() -> Iterator[None]:
    """A stop signal that no event loop takes does nothing until the test ends; then each
    stop signal's handler is what it was before."""
    saved = {signum: signal.getsignal(signum) for signum in _STOP_SIGNALS}
    for signum in saved:
        signal.signal(signum, _stand_in_stop_handler)
    try:
        yield
    finally:
        for signum, handler in saved.items():
            signal.signal(signum, handler if handler is not None else signal.SIG_DFL)


@pytest.fixture
def exit_sweep_log() -> Iterator[list[str]]:
    """Every warning the Docker client module logs while the test runs."""
    lines: list[str] = []
    handler = _Recorded(lines)
    log = logging.getLogger(docker_client.__name__)
    log.addHandler(handler)
    try:
        yield lines
    finally:
        log.removeHandler(handler)


class _NotFoundError(Exception):
    """What the Docker client raises for a container that no longer exists."""

    status_code = 404


class _Api:
    """A Docker API stand-in that records, in order, every call a cut makes."""

    def __init__(
        self,
        attached: list[str],
        *,
        stuck: tuple[str, ...] = (),
        inspect_error: Exception | None = None,
        kill_error: Exception | None = None,
        hold: threading.Event | None = None,
        delay: float = 0.0,
    ) -> None:
        self.attached = list(attached)
        self.stuck = stuck
        self.inspect_error = inspect_error
        self.kill_error = kill_error
        self.hold = hold
        self.delay = delay
        self.events: list[str] = []

    def disconnect_container_from_network(
        self, _container: str, network: str, force: bool = False
    ) -> None:
        if self.hold is not None:
            self.hold.wait(5)
        time.sleep(self.delay)
        self.events.append(f"disconnect {network} force={force}")
        if network in self.attached and network not in self.stuck:
            self.attached.remove(network)

    def inspect_container(self, _container: str) -> dict[str, Any]:
        self.events.append("inspect")
        if self.inspect_error is not None:
            raise self.inspect_error
        return {"NetworkSettings": {"Networks": {name: {} for name in self.attached}}}

    def kill(self, _container: str) -> None:
        self.events.append("kill")
        if self.kill_error is not None:
            raise self.kill_error
        self.attached.clear()


class _CutClient:
    """The cut's own Docker client, around an API stand-in."""

    def __init__(self, api: _Api) -> None:
        self.api = api
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _CuttableClient(_Client):
    """A sandbox client, as a backend returns it, whose cut a stop can arm."""

    def __init__(self, api: _Api) -> None:
        super().__init__()
        self.api = api

    def network_cut_target(self, _session: Any) -> stop_module.CutTarget:
        return _target(self.api)


class _UncuttableClient(_Client):
    """A sandbox client whose cut cannot be armed."""

    def network_cut_target(self, _session: Any) -> NoReturn:
        raise ConnectionError("the daemon did not describe the container")


class _Container:
    """A sandbox as the Docker client lists it."""

    def __init__(
        self,
        container_id: str,
        labels: dict[str, str],
        networks: list[str],
        events: list[str],
        *,
        status: str = "running",
    ) -> None:
        self.id = container_id
        self.short_id = container_id
        self.labels = labels
        self.status = status
        self.attrs = {"NetworkSettings": {"Networks": {name: {} for name in networks}}}
        self.removed = False
        self._events = events

    def remove(self, *, force: bool = False) -> None:
        self._events.append(f"remove {self.id} force={force}")
        self.removed = True


class _SweepClient:
    """A Docker client stand-in that lists sandboxes as the daemon does and records what a
    sweep does; it also creates sandboxes, as a scan's own client does."""

    def __init__(self, containers: list[_Container], events: list[str]) -> None:
        self.containers = types.SimpleNamespace(list=self._list, create=self._create)
        self.images = types.SimpleNamespace(get=lambda image: image)
        self.api = types.SimpleNamespace(disconnect_container_from_network=self._disconnect)
        self.listings: list[dict[str, Any]] = []
        self.closed = False
        self._held = list(containers)
        self._events = events

    def close(self) -> None:
        self.closed = True

    def _list(self, **options: Any) -> list[_Container]:
        self.listings.append(options)
        return [held for held in self._held if not held.removed and _daemon_lists(held, options)]

    def _create(self, **options: Any) -> _Container:
        created = _Container(
            f"sandbox-{len(self._held) + 1}",
            dict(options.get("labels") or {}),
            ["bridge"],
            self._events,
            status="created",
        )
        self._held.append(created)
        return created

    def _disconnect(self, container: str, network: str, *, force: bool = False) -> None:
        self._events.append(f"disconnect {container} from {network} force={force}")


class _Recorded(logging.Handler):
    """Keeps the message of every warning, or worse, that it is handed."""

    def __init__(self, lines: list[str]) -> None:
        super().__init__(logging.WARNING)
        self.lines = lines

    @override
    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(record.getMessage())


def _daemon_lists(container: _Container, options: dict[str, Any]) -> bool:
    """Whether the Docker daemon lists the container for these options of a list call."""
    filters = options.get("filters") or {}
    status = filters.get("status")
    if status is None:
        in_state = bool(options.get("all")) or container.status in _UP_STATES
    else:
        in_state = container.status == status
    key, has_value, value = str(filters.get("label", "")).partition("=")
    has_label = key in container.labels and (not has_value or container.labels[key] == value)
    return in_state and (not key or has_label)


def _target(api: _Api, networks: tuple[str, ...] = ("bridge",)) -> stop_module.CutTarget:
    return stop_module.CutTarget(
        client=_CutClient(api), container_id="sandbox-1", networks=networks
    )


def _armed(api: _Api, networks: tuple[str, ...] = ("bridge",)) -> stop_module.ScanStop:
    """A stop armed with a stand-in sandbox."""
    stop = stop_module.ScanStop("cut-probe")
    stop.arm(_target(api, networks))
    return stop


def _labels(
    *, pid: str, host: str = _HOST, user: str = _USER, started: str = _STARTED
) -> dict[str, str]:
    return {
        owner.OWNER_HOST_LABEL: host,
        owner.OWNER_USER_LABEL: user,
        owner.OWNER_PID_LABEL: pid,
        owner.OWNER_STARTED_LABEL: started,
    }


def _tool_context(context: dict[str, Any], tool_name: str, arguments: str) -> ToolContext[Any]:
    """A tool call's context, built as the agents SDK builds it for a function call
    (agents/run_internal/tool_execution.py: ToolContext.from_agent_context)."""
    call = ResponseFunctionToolCall(
        type="function_call", name=tool_name, arguments=arguments, call_id="call-probe"
    )
    return ToolContext.from_agent_context(
        RunContextWrapper(context=context), call.call_id, tool_call=call
    )


async def _invoke(tool: Any, context: dict[str, Any], arguments: str) -> Any:
    """Call a tool as the agents SDK does, bounded so that a tool that blocks fails the test."""
    ctx = _tool_context(context, tool.name, arguments)
    return await asyncio.wait_for(tool.on_invoke_tool(ctx, arguments), 5)


def _probe_function(calls: list[str]) -> FunctionTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        calls.append("probe")
        return "ran"

    return FunctionTool(
        name="probe",
        description="Records that it ran.",
        params_json_schema={"type": "object", "properties": {}, "additionalProperties": False},
        on_invoke_tool=invoke,
    )


def _probe_custom(calls: list[str]) -> CustomTool:
    async def invoke(_ctx: Any, _raw_input: str) -> str:
        calls.append("probe")
        return "ran"

    return CustomTool(name="probe", description="Records that it ran.", on_invoke_tool=invoke)


def _gated_probe(kind: str, calls: list[str]) -> Any:
    """A probe tool as an agent holds it, wrapped on the path its kind takes."""
    if kind == "function":
        return factory._prepared_tool(_probe_function(calls), strict_schemas=True)
    toolset = types.SimpleNamespace(
        probe=_probe_custom(calls) if kind == "custom" else _probe_function(calls)
    )
    if kind == "shell":
        factory._configure_shell_tools(toolset, chat_completions=False)
    else:
        factory._configure_filesystem_tools(toolset, chat_completions=False)
    return toolset.probe


def _ending(kind: str) -> BaseException | None:
    """How the root agent's loop ends a scan of this kind."""
    if kind == "budget":
        return BudgetExceededError("the scan reached its budget")
    if kind == "rate-limited":
        request = httpx.Request("POST", "https://api.example.test/v1/responses")
        return RateLimitError(
            "rate limited", response=httpx.Response(429, request=request), body=None
        )
    if kind == "interrupted":
        return asyncio.CancelledError()
    if kind == "failed":
        return RuntimeError("the model route failed")
    return None


async def _scan_until_cancelled(events: list[str]) -> None:
    try:
        await asyncio.sleep(3600)
    except asyncio.CancelledError:
        events.append("scan cancelled")
        raise


def _cli_args(run_name: str) -> Any:
    return types.SimpleNamespace(
        targets_info=[{"original": "http://app.example.test"}],
        run_name=run_name,
        instruction=None,
        scan_mode="quick",
        non_interactive=True,
        local_sources=[],
        workspace_files=[],
        scope_mode="auto",
        diff_base=None,
        diff_scope={"active": False},
        user_explicit_instruction=None,
        interactive=False,
        max_budget_usd=None,
        max_turns=10,
    )


async def _scan_ends_at_once(**_kwargs: Any) -> None:
    return None


def _stand_in_stop_handler(_signum: int, _frame: Any) -> None:
    """Holds a stop signal for the test without acting on it."""


def _use_docker_backend(monkeypatch: pytest.MonkeyPatch, backend: Any) -> None:
    """Stand in for the Docker backend itself: the sweep runs for it alone."""
    monkeypatch.setitem(backends._BACKENDS, "docker", backend)
    monkeypatch.setattr(session_manager, "bootstrap_caido", _no_caido)
    settings = _Settings(runtime=_RuntimeSettings(backend="docker"))
    monkeypatch.setattr(session_manager, "load_settings", lambda: settings)


def _run_json(run_dir: Path) -> dict[str, Any]:
    return json.loads((run_dir / "run.json").read_text(encoding="utf-8"))


def _stopped_lines(run_dir: Path) -> list[str]:
    """The report header's lines about stops."""
    report = (run_dir / "penetration_test_report.md").read_text(encoding="utf-8")
    header = report.split("# Executive Summary")[0]
    return [line for line in header.splitlines() if line.startswith("**Stopped:**")]


def _stopped_line(record: dict[str, Any]) -> str:
    return (
        f"**Stopped:** {record['reason']} at {record['received_at']}; "
        f"sandbox network cut at {record['cut_at']}."
    )


def _swept(container: str, state: str) -> dict[str, str]:
    """A sweep's entry for an orphan of the exited owner, cut and removed in full."""
    return {
        "container": container,
        "state": state,
        "owner_pid": _DEAD_PID,
        "result": owner.ORPHAN_SWEPT,
    }


def _sandbox_session(container_id: str = "sandbox-1") -> Any:
    return types.SimpleNamespace(
        _inner=types.SimpleNamespace(state=types.SimpleNamespace(container_id=container_id))
    )


def _console(lines: list[str]) -> Any:
    """A console that keeps each line it is given to print."""
    return types.SimpleNamespace(print=lambda text, **_options: lines.append(text))


def _refused(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise ConnectionRefusedError("no Docker daemon is asked during tests")


def _do_nothing(*_args: Any, **_kwargs: Any) -> None:
    """Stands in for a step main() takes around a scan."""


async def _no_scan(_args: Any) -> None:
    """A stand-in scan that ends before any sandbox is made."""


def _own_listing() -> dict[str, Any]:
    """The one listing the exit sweep makes: every sandbox labelled with this pid."""
    return {
        "all": True,
        "filters": {"label": f"{owner.OWNER_PID_LABEL}={os.getpid()}"},
        "ignore_removed": True,
    }


def _main_ready(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, run_name: str, *, interactive: bool = False
) -> ReportState:
    """Make main() ready to run one scan, on the command line or in the TUI, with everything
    around the scan replaced: no update check, no Docker check or pull, no warm-up, no
    model preflight and no telemetry. The run's report lands in ``tmp_path``."""
    monkeypatch.chdir(tmp_path)
    state = ReportState(run_name)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    args = tui_args() if interactive else _cli_args(run_name)
    args.run_name = run_name
    args.non_interactive = not interactive
    monkeypatch.setattr(main_module.sys, "argv", ["zen"])
    for name in (
        "configure_dependency_logging",
        "start_import_warmup",
        "start_background_check",
        "check_docker_installed",
        "pull_docker_image",
        "validate_environment",
        "wait_for_import_warmup",
        "_bootstrap_scan",
        "report_error",
        "display_completion_message",
        "notify_update",
    ):
        monkeypatch.setattr(main_module, name, _do_nothing)
    monkeypatch.setattr(main_module, "parse_arguments", lambda: args)
    monkeypatch.setattr(main_module, "prompt_update_if_available", lambda _console: False)
    monkeypatch.setattr(main_module.posthog, "end", _do_nothing)
    monkeypatch.setattr(main_module.scarf, "end", _do_nothing)
    return state


def _scan_with(monkeypatch: pytest.MonkeyPatch, scan: Callable[[Any], Awaitable[None]]) -> None:
    """main()'s scan, on the command line and in the TUI alike, is ``scan``."""
    monkeypatch.setattr(cli, "run_cli", scan)
    monkeypatch.setattr(main_module, "run_tui", scan)


def _scan_torn_down(daemon: _SweepClient) -> Callable[[Any], Awaitable[None]]:
    """A stand-in scan whose sandbox its own teardown removed."""

    async def scan(_args: Any) -> None:
        sandbox = await docker_client.ZenDockerSandboxClient(daemon)._create_container(_IMAGE)
        sandbox.remove(force=True)

    return scan


def _end_scan(ending: str, run_name: str, state: ReportState) -> None:
    """End a stand-in scan as the ending named does."""
    if ending == "cli-stopped":
        cli._stop_signal_handler(run_name, state, _console([]))(signal.SIGINT, None)
    if ending == "cli-failed":
        raise RuntimeError("the scan failed")
    if ending == "tui-stopped":
        raise go_tui.TuiStoppedError("signal SIGTERM")


def _stand_in_tui(
    monkeypatch: pytest.MonkeyPatch, runtime: GoTuiRuntime, sidecar: Callable[[object], Any]
) -> dict[int, tuple[Callable[..., None], tuple[Any, ...]]]:
    """Give ``runtime`` a stand-in sidecar, whose wait is ``sidecar``, a stand-in server and
    a signal registry of its own. Returns the handlers the runtime binds, by signal."""
    handlers: dict[int, tuple[Callable[..., None], tuple[Any, ...]]] = {}

    def _add_signal_handler(signum: int, callback: Callable[..., None], *args: Any) -> None:
        handlers[signum] = (callback, args)

    def _remove_signal_handler(signum: int) -> bool:
        return handlers.pop(signum, None) is not None

    async def _launch(*_args: Any) -> tuple[Any, None]:
        return types.SimpleNamespace(returncode=None), None

    async def _nothing(*_args: Any) -> None:
        return None

    loop = asyncio.get_running_loop()
    monkeypatch.setattr(loop, "add_signal_handler", _add_signal_handler)
    monkeypatch.setattr(loop, "remove_signal_handler", _remove_signal_handler)
    monkeypatch.setattr(runtime, "binary_command", lambda: ["test-sidecar"])
    monkeypatch.setattr(runtime, "_start_preparation", lambda: asyncio.create_task(_nothing()))
    monkeypatch.setattr(runtime, "sync_state", _nothing)
    monkeypatch.setattr(runtime.server, "start", _nothing)
    monkeypatch.setattr(runtime.server, "close", _nothing)
    monkeypatch.setattr(go_tui, "launch_tui_process", _launch)
    monkeypatch.setattr(go_tui, "wait_process", sidecar)
    monkeypatch.setattr(go_tui, "terminate_process", _nothing)
    return handlers


def _stand_in_tui_for_main(
    monkeypatch: pytest.MonkeyPatch, sidecar: Callable[[object], Any]
) -> None:
    """The TUI main() starts gets a stand-in sidecar, whose wait is ``sidecar``, and a
    stand-in server, and prepares no scan."""

    async def _launch(*_args: Any) -> tuple[Any, None]:
        return types.SimpleNamespace(returncode=None), None

    async def _nothing(*_args: Any) -> None:
        return None

    monkeypatch.setattr(go_tui, "launch_tui_process", _launch)
    monkeypatch.setattr(go_tui, "wait_process", sidecar)
    monkeypatch.setattr(go_tui, "terminate_process", _nothing)
    monkeypatch.setattr(GoTuiRuntime, "binary_command", staticmethod(lambda: ["test-sidecar"]))
    monkeypatch.setattr(
        GoTuiRuntime, "_start_preparation", lambda _self: asyncio.ensure_future(_nothing())
    )
    monkeypatch.setattr(GoTuiRuntime, "sync_state", _nothing)
    monkeypatch.setattr(TuiBackendServer, "start", _nothing)
    monkeypatch.setattr(TuiBackendServer, "close", _nothing)


def _tui_with_scan(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, scan_id: str
) -> tuple[GoTuiRuntime, _Api, ReportState]:
    """A TUI session whose scan runs, with a sandbox armed for the scan's stop."""
    monkeypatch.chdir(tmp_path)
    api = _Api(["bridge"])
    stop_module.begin_scan_stop(scan_id).arm(_target(api))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    runtime = GoTuiRuntime(tui_args())
    runtime.scan_config = {"run_name": scan_id}
    runtime.scan_task = asyncio.create_task(_scan_until_cancelled(api.events))
    return runtime, api, state


def _sidecar_running(up: asyncio.Event) -> Callable[[object], Awaitable[int]]:
    """A stand-in sidecar's wait: the TUI is up, and it runs until its run is cancelled."""

    async def wait(_process: object) -> int:
        up.set()
        await asyncio.Event().wait()
        return 0

    return wait


def test_the_cut_disconnects_every_network_and_confirms_none_is_left() -> None:
    api = _Api(["bridge", "lab"])
    stop = _armed(api, networks=("bridge", "lab"))

    stop.request("signal SIGTERM")

    assert stop.wait()
    assert api.events == ["disconnect bridge force=True", "disconnect lab force=True", "inspect"]
    assert api.attached == []
    record = stop.record()
    assert record["cut_result"] == "cut"
    assert record["cut_at"] is not None


def test_a_network_attached_since_the_scan_began_is_cut_too() -> None:
    api = _Api(["bridge", "late"])
    stop = _armed(api)

    stop.request("scan ended")

    assert stop.wait()
    assert api.events == [
        "disconnect bridge force=True",
        "inspect",
        "disconnect late force=True",
        "inspect",
    ]
    assert api.attached == []
    assert stop.record()["cut_result"] == "cut"


def test_a_disconnect_that_cannot_be_confirmed_ends_the_sandbox_instead() -> None:
    api = _Api(["bridge"], stuck=("bridge",))
    stop = _armed(api)

    stop.request("signal SIGINT")

    assert stop.wait()
    assert api.events[-1] == "kill"
    assert api.attached == []
    assert stop.record()["cut_result"] == _KILLED


def test_a_cut_that_fails_is_recorded_and_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    unreachable = ConnectionError("daemon unreachable")
    api = _Api(["bridge"], inspect_error=unreachable, kill_error=unreachable)
    escaped: list[Any] = []
    monkeypatch.setattr(threading, "excepthook", escaped.append)
    stop = _armed(api)

    stop.request("signal SIGTERM")

    assert stop.wait()
    record = stop.record()
    assert record["cut_result"] == f"not cut ({_UNREACHABLE}, then {_UNREACHABLE})"
    assert record["cut_at"] is not None
    assert escaped == []


def test_a_sandbox_that_is_already_gone_counts_as_cut() -> None:
    gone = _NotFoundError("No such container: sandbox-1")
    api = _Api([], inspect_error=gone, kill_error=gone)
    stop = _armed(api)

    stop.request("scan ended")

    assert stop.wait()
    assert stop.record()["cut_result"] == "cut (the sandbox was already gone)"
    assert "kill" not in api.events


def test_a_second_stop_neither_repeats_nor_skips_the_cut() -> None:
    hold = threading.Event()
    api = _Api(["bridge"], hold=hold)
    stop = _armed(api)
    try:
        stop.request("signal SIGINT")
        cutting = stop._thread
        stop.request("signal SIGINT")
        stop.request("interrupted")
        assert stop._thread is cutting
        assert cutting is not None
        assert cutting.daemon is False
    finally:
        hold.set()

    assert stop.wait()
    record = stop.record()
    assert record["reason"] == "signal SIGINT"
    assert record["cut_result"] == "cut"
    assert api.events.count("disconnect bridge force=True") == 1


def test_a_stop_received_before_the_sandbox_is_up_cuts_once_it_is_armed() -> None:
    stop = stop_module.ScanStop("armed-late")
    stop.request("signal SIGINT")
    assert stop.record()["cut_result"] == "not cut (no sandbox network was armed)"
    api = _Api(["bridge"])

    stop.arm(_target(api))

    assert stop.wait()
    record = stop.record()
    assert record["reason"] == "signal SIGINT"
    assert record["cut_result"] == "cut"
    assert api.attached == []


@pytest.mark.usefixtures("production_docker_clients")
def test_the_cut_has_a_docker_client_of_its_own_with_a_short_timeout(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made: list[dict[str, Any]] = []
    read_from_environment: list[dict[str, Any]] = []
    own_client = types.SimpleNamespace(
        containers=types.SimpleNamespace(list=lambda **_filters: []), close=lambda: None
    )

    def _docker_client(**options: Any) -> object:
        made.append(options)
        return own_client

    def _from_env(**options: Any) -> object:
        read_from_environment.append(options)
        return own_client

    monkeypatch.setattr(docker_client.docker, "DockerClient", _docker_client)
    monkeypatch.setattr(docker_client.docker, "from_env", _from_env)
    # The scan's client was made from a connection naming one daemon and the environment
    # names another, so that which one each client was made from shows. Each connection
    # carries a timeout of its own, which the cut's and the sweep's settings win over.
    monkeypatch.setattr(
        docker_client, "docker_connection", lambda: {"base_url": _DAEMON_B, "timeout": 60}
    )
    container = types.SimpleNamespace(
        attrs={"NetworkSettings": {"Networks": {"lab": {}, "bridge": {}}}}
    )
    daemon = types.SimpleNamespace(
        containers=types.SimpleNamespace(get=lambda _id: container),
        api=types.SimpleNamespace(api_version="1.47"),
    )
    client = docker_client.ZenDockerSandboxClient(daemon)
    client.zen_connection = {"base_url": _DAEMON_A, "timeout": 60}

    target = client.network_cut_target(_sandbox_session())
    swept = docker_client.sweep_orphan_sandboxes()

    assert target.client is own_client
    assert target.container_id == "sandbox-1"
    assert target.networks == ("bridge", "lab")
    assert swept == []
    # The cut's client speaks the version the scan's client agreed, so making it asks the
    # daemon nothing; the sweep's client is made before any scan client exists.
    assert made == [
        {"base_url": _DAEMON_A, "timeout": stop_module.CUT_REQUEST_TIMEOUT_S, "version": "1.47"},
        {"base_url": _DAEMON_B, "timeout": docker_client.SWEEP_REQUEST_TIMEOUT_S},
    ]
    assert read_from_environment == []


@pytest.mark.usefixtures("production_docker_clients")
def test_a_test_that_asks_for_the_production_docker_clients_gets_the_real_factories() -> None:
    assert docker_client.DEFAULT_CUT_CLIENT is docker_client.make_cut_client
    assert docker_client.DEFAULT_SWEEP_CLIENT is docker_client.make_sweep_client


def test_every_other_test_gets_docker_clients_that_reach_no_daemon() -> None:
    # Checked first: with the real factories in place, the test stops before making a client.
    assert docker_client.DEFAULT_CUT_CLIENT is not docker_client.make_cut_client
    assert docker_client.DEFAULT_SWEEP_CLIENT is not docker_client.make_sweep_client
    own = docker_client.DEFAULT_CUT_CLIENT({}, "1.47")
    stop = stop_module.ScanStop("no-daemon")
    stop.arm(stop_module.CutTarget(client=own, container_id="sandbox-1", networks=("bridge",)))

    stop.request("signal SIGTERM")

    assert stop.wait()
    assert str(stop.record()["cut_result"]).startswith("not cut (ConnectionRefusedError")
    assert docker_client.sweep_orphan_sandboxes() == []


def test_a_sandbox_whose_docker_connection_is_unknown_is_never_armed() -> None:
    inspected: list[str] = []

    def _inspect(container_id: str) -> Any:
        inspected.append(container_id)
        return types.SimpleNamespace(attrs={"NetworkSettings": {"Networks": {"bridge": {}}}})

    daemon = types.SimpleNamespace(
        containers=types.SimpleNamespace(get=_inspect),
        api=types.SimpleNamespace(api_version="1.47"),
    )
    client = docker_client.ZenDockerSandboxClient(daemon)

    with pytest.raises(RuntimeError, match="Docker connection is not known"):
        client.network_cut_target(_sandbox_session())

    assert inspected == []


@pytest.mark.asyncio
async def test_the_docker_backend_builds_the_scan_client_from_one_connection_and_hands_it_on(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    made: list[dict[str, Any]] = []
    started: list[str] = []
    scan_client = types.SimpleNamespace(api=types.SimpleNamespace(api_version="1.47"))

    def _docker_client(**options: Any) -> object:
        made.append(options)
        return scan_client

    async def _start() -> None:
        started.append("started")

    async def _create(_self: Any, **_kwargs: Any) -> Any:
        return types.SimpleNamespace(start=_start)

    monkeypatch.setattr(docker_client, "docker_connection", lambda: {"base_url": _DAEMON_A})
    monkeypatch.setattr(docker_client.docker, "DockerClient", _docker_client)
    monkeypatch.setattr(docker_client.docker, "from_env", _refused)
    monkeypatch.setattr(docker_client.ZenDockerSandboxClient, "create", _create)

    client, _session = await backends._docker_backend(
        image=_IMAGE, manifest=Manifest(), exposed_ports=(48080,), bind_mounts=[]
    )

    assert made == [{"base_url": _DAEMON_A}]
    assert client.docker_client is scan_client
    assert client.zen_connection == {"base_url": _DAEMON_A}
    assert started == ["started"]


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("kind", "reason", "raised"),
    [
        pytest.param("finished", "scan ended", None, id="finished"),
        pytest.param("budget", "budget exceeded", None, id="budget"),
        pytest.param("rate-limited", "rate limited", None, id="rate-limited"),
        pytest.param("interrupted", "interrupted", asyncio.CancelledError, id="interrupted"),
        pytest.param("failed", "failed", RuntimeError, id="failed"),
    ],
)
async def test_a_stop_cuts_the_sandbox_network_before_any_agent_is_cancelled(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    kind: str,
    reason: str,
    raised: type[BaseException] | None,
) -> None:
    scan_id = f"order-{kind}"
    _wire_runner(monkeypatch, tmp_path)
    api = _Api(["bridge"])

    class _Coordinator(AgentCoordinator):
        @override
        async def cancel_descendants(self, agent_id: str) -> None:
            api.events.append("agents cancelled")
            await super().cancel_descendants(agent_id)

    async def _root(**_kwargs: Any) -> None:
        stop_module.scan_stop(scan_id).arm(_target(api))
        ending = _ending(kind)
        if ending is not None:
            raise ending

    monkeypatch.setattr(runner, "run_agent_loop", _root)
    scan = runner.run_zen_scan(
        scan_config={"targets": [], "scan_mode": "quick"},
        scan_id=scan_id,
        image=_IMAGE,
        coordinator=_Coordinator(),
    )
    if raised is None:
        await scan
    else:
        with pytest.raises(raised):
            await scan

    record = stop_module.scan_stop(scan_id).record()
    assert record["reason"] == reason
    assert record["cut_result"] == "cut"
    assert api.events == ["disconnect bridge force=True", "inspect", "agents cancelled"]


@pytest.mark.asyncio
async def test_every_agent_the_runner_starts_holds_the_scans_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    scan_id = "context-stop"
    _wire_runner(monkeypatch, tmp_path)
    contexts: dict[str, dict[str, Any]] = {}
    child_started = asyncio.Event()

    async def _child(**kwargs: Any) -> None:
        contexts["child"] = kwargs["context"]
        child_started.set()

    async def _root(**kwargs: Any) -> None:
        context = kwargs["context"]
        contexts["root"] = context
        await context["spawn_child_agent"](
            parent_ctx=context, name="Child", task="probe", skills=[], parent_history=[]
        )
        await asyncio.wait_for(child_started.wait(), 5)

    monkeypatch.setattr(runner, "run_agent_loop", _root)
    monkeypatch.setattr(execution, "run_agent_loop", _child)

    await runner.run_zen_scan(
        scan_config={"targets": [], "scan_mode": "quick"},
        scan_id=scan_id,
        image=_IMAGE,
        coordinator=AgentCoordinator(),
    )

    stop = stop_module.scan_stop(scan_id)
    assert stop.requested
    for name in ("root", "child"):
        assert contexts[name].get(stop_module.STOP_CONTEXT_KEY) is stop
        assert stop_module.stop_notice(contexts[name]) == stop_module.STOP_NOTICE


@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
def test_a_stop_signal_cuts_the_network_before_the_run_is_recorded_and_the_process_exits(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = f"signal-{name.lower()}"
    api = _Api(["bridge"], delay=0.2)
    stop_module.begin_scan_stop(scan_id).arm(_target(api))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    record_run = state.cleanup

    def _cleanup(status: str = "stopped") -> None:
        api.events.append(f"run recorded as {status}")
        record_run(status)

    monkeypatch.setattr(state, "cleanup", _cleanup)
    printed: list[str] = []
    handler = cli._stop_signal_handler(scan_id, state, types.SimpleNamespace(print=printed.append))

    with pytest.raises(SystemExit) as exited:
        handler(getattr(signal, name), None)

    assert exited.value.code == 1
    assert api.events == ["disconnect bridge force=True", "inspect", "run recorded as interrupted"]
    run_json = _run_json(tmp_path / "zen_runs" / scan_id)
    assert run_json["status"] == "interrupted"
    assert [stop["reason"] for stop in run_json["stops"]] == [f"signal {name}"]
    assert run_json["stops"][0]["cut_result"] == "cut"
    assert printed == [stop_module.stop_acknowledgment(run_json["stops"][0])]


def test_a_repeated_stop_signal_in_the_cli_says_so_and_returns(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "signal-repeated"
    api = _Api(["bridge"])
    stop_module.begin_scan_stop(scan_id).arm(_target(api))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    record_run = state.cleanup
    recorded: list[str] = []

    def _cleanup(status: str = "stopped") -> None:
        recorded.append(status)
        record_run(status)

    monkeypatch.setattr(state, "cleanup", _cleanup)
    printed: list[str] = []
    handler = cli._stop_signal_handler(scan_id, state, _console(printed))

    with pytest.raises(SystemExit) as exited:
        handler(signal.SIGINT, None)
    handler(signal.SIGTERM, None)

    run_json = _run_json(tmp_path / "zen_runs" / scan_id)
    assert exited.value.code == stop_module.STOP_EXIT_STATUS
    assert recorded == ["interrupted"]
    assert [stop["reason"] for stop in run_json["stops"]] == ["signal SIGINT"]
    assert api.events.count("disconnect bridge force=True") == 1
    assert printed == [
        stop_module.stop_acknowledgment(run_json["stops"][0]),
        stop_module.STOP_UNDER_WAY,
    ]


@pytest.mark.asyncio
@pytest.mark.usefixtures("stop_signal_handlers_restored")
async def test_the_cli_binds_sigint_sigterm_and_sighup_to_the_stop_handler(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    working_tree = Path.cwd()
    monkeypatch.chdir(tmp_path)
    made: list[str] = []

    def _make_handler(
        scan_id: str, _report_state: Any, _console: Any
    ) -> Callable[[int, Any], None]:
        made.append(scan_id)
        return _stand_in_stop_handler

    monkeypatch.setattr(cli, "_stop_signal_handler", _make_handler)
    monkeypatch.setattr(cli.atexit, "register", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(cli, "_resolve_sandbox_image", lambda: _IMAGE)
    monkeypatch.setattr(cli, "run_zen_scan", _scan_ends_at_once)

    await cli.run_cli(_cli_args("cli-signals"))

    assert made == ["cli-signals"]
    bound = {signum: signal.getsignal(signum) for signum in _STOP_SIGNALS}
    assert bound == dict.fromkeys(_STOP_SIGNALS, _stand_in_stop_handler)
    assert (tmp_path / "zen_runs" / "cli-signals" / "run.json").is_file()
    assert not (working_tree / "zen_runs" / "cli-signals").exists()


@pytest.mark.asyncio
async def test_quitting_the_tui_cuts_the_network_before_the_scan_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "tui-quit"
    api = _Api(["bridge"])
    stop_module.begin_scan_stop(scan_id).arm(_target(api))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    runtime = GoTuiRuntime(tui_args())
    runtime.scan_config = {"run_name": scan_id}
    runtime.scan_task = asyncio.create_task(_scan_until_cancelled(api.events))
    await asyncio.sleep(0)

    await runtime.quit()

    assert api.events == ["disconnect bridge force=True", "inspect", "scan cancelled"]
    stops = state.run_record["stops"]
    assert [stop["reason"] for stop in stops] == ["tui quit"]
    assert stops[0]["cut_result"] == "cut"


@pytest.mark.asyncio
@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
async def test_a_stop_signal_stops_the_tui_scan_network_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    runtime, api, state = _tui_with_scan(monkeypatch, tmp_path, f"tui-{name.lower()}")
    ui_running = asyncio.Event()
    handlers = _stand_in_tui(monkeypatch, runtime, _sidecar_running(ui_running))

    run_task = asyncio.create_task(runtime.run())
    try:
        await asyncio.wait_for(ui_running.wait(), 5)
        callback, callback_args = handlers[getattr(signal, name)]
        callback(*callback_args)
        await asyncio.wait([run_task], timeout=10)
    finally:
        if not run_task.done():
            run_task.cancel()
            await asyncio.wait([run_task], timeout=10)

    assert run_task.cancelled()
    assert api.events == ["disconnect bridge force=True", "inspect", "scan cancelled"]
    stops = state.run_record["stops"]
    assert [stop["reason"] for stop in stops] == [f"signal {name}"]
    assert stops[0]["cut_result"] == "cut"
    assert handlers == {}


@pytest.mark.asyncio
async def test_a_cancelled_tui_run_cuts_the_network_before_the_scan_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, api, state = _tui_with_scan(monkeypatch, tmp_path, "tui-cancelled")
    ui_running = asyncio.Event()
    _stand_in_tui(monkeypatch, runtime, _sidecar_running(ui_running))
    run_task = asyncio.create_task(runtime.run())
    await asyncio.wait_for(ui_running.wait(), 5)

    run_task.cancel()
    await asyncio.wait([run_task], timeout=10)

    assert run_task.cancelled()
    assert api.events == ["disconnect bridge force=True", "inspect", "scan cancelled"]
    assert [stop["reason"] for stop in state.run_record["stops"]] == ["interrupted"]


@pytest.mark.asyncio
async def test_a_failed_tui_sidecar_cuts_the_network_before_the_scan_is_cancelled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    runtime, api, state = _tui_with_scan(monkeypatch, tmp_path, "tui-failed")

    async def _sidecar(_process: object) -> int:
        return 3

    _stand_in_tui(monkeypatch, runtime, _sidecar)

    with pytest.raises(RuntimeError, match="exited with status 3"):
        await runtime.run()

    assert api.events == ["disconnect bridge force=True", "inspect", "scan cancelled"]
    assert [stop["reason"] for stop in state.run_record["stops"]] == ["tui failed"]


@pytest.mark.asyncio
async def test_a_repeated_stop_signal_in_the_tui_is_ignored() -> None:
    scan_id = "tui-repeated"
    stop = stop_module.begin_scan_stop(scan_id)
    runtime = GoTuiRuntime(tui_args())
    runtime.scan_config = {"run_name": scan_id}
    scan_task = asyncio.create_task(_scan_until_cancelled([]))
    runtime.scan_task = scan_task
    main_task = asyncio.create_task(asyncio.sleep(3600))
    try:
        runtime._on_stop_signal(signal.SIGINT, main_task)
        runtime._on_stop_signal(signal.SIGTERM, main_task)
        cancellations = main_task.cancelling()
    finally:
        for task in (main_task, scan_task):
            task.cancel()
        await asyncio.wait([main_task, scan_task], timeout=5)

    assert cancellations == 1
    assert stop.reason == "signal SIGINT"
    assert runtime._stop_reason == "signal SIGINT"
    assert runtime._stop_signal == "signal SIGINT"


@pytest.mark.parametrize("name", ["SIGINT", "SIGTERM", "SIGHUP"])
@pytest.mark.usefixtures("stop_signals_held")
def test_a_tui_stopped_by_a_signal_exits_with_the_stop_status_and_no_traceback(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, name: str
) -> None:
    run_name = f"tui-{name.lower()}-exit"
    _main_ready(monkeypatch, tmp_path, run_name, interactive=True)

    async def _sidecar(_process: object) -> int:
        os.kill(os.getpid(), getattr(signal, name))
        await asyncio.sleep(5)
        return 0

    _stand_in_tui_for_main(monkeypatch, _sidecar)

    with pytest.raises(SystemExit) as exited:
        main_module.main()

    # A stop leaves as SystemExit, which prints no traceback, never as the cancellation.
    assert exited.value.code == stop_module.STOP_EXIT_STATUS
    assert _run_json(tmp_path / "zen_runs" / run_name)["status"] == "interrupted"


@pytest.mark.usefixtures("stop_signal_handlers_restored")
def test_a_cancellation_of_the_tui_run_without_a_stop_is_not_reported_as_a_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_name = "tui-cancelled-run"
    _main_ready(monkeypatch, tmp_path, run_name, interactive=True)

    async def _sidecar(_process: object) -> int:
        run = asyncio.current_task()
        assert run is not None
        run.cancel()
        await asyncio.sleep(5)
        return 0

    _stand_in_tui_for_main(monkeypatch, _sidecar)

    with pytest.raises(asyncio.CancelledError):
        main_module.main()

    assert _run_json(tmp_path / "zen_runs" / run_name)["status"] == "failed"


@pytest.mark.asyncio
async def test_every_tool_an_agent_holds_returns_the_stop_notice_after_a_stop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Were a tool not gated, it would run: here, where nothing it writes reaches the
    # working tree, and with a proxy address that fails at once.
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("ZEN_CAIDO_URL", "invalid")
    root = factory.build_zen_agent(
        name="root", is_root=True, interactive=True, instructions_override="probe"
    )
    child = factory.build_zen_agent(name="child", is_root=False, instructions_override="probe")
    stop = stop_module.ScanStop("tools-after-stop")
    stop.request("signal SIGTERM")
    context = {stop_module.STOP_CONTEXT_KEY: stop}

    results = {
        f"{agent.name}/{tool.name}": await _invoke(tool, context, "{}")
        for agent in (root, child)
        for tool in agent.tools
    }

    assert len(results) > len(factory._BASE_TOOLS)
    ran = {name: result for name, result in results.items() if result != stop_module.STOP_NOTICE}
    assert ran == {}


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["function", "shell", "filesystem", "custom"])
async def test_a_gated_tool_runs_until_the_stop_and_never_after(kind: str) -> None:
    calls: list[str] = []
    tool = _gated_probe(kind, calls)
    stop = stop_module.ScanStop(f"probe-{kind}")
    context = {stop_module.STOP_CONTEXT_KEY: stop}

    before = await _invoke(tool, context, "{}")
    stop.request("signal SIGINT")
    after = await _invoke(tool, context, "{}")

    assert before == "ran"
    assert after == stop_module.STOP_NOTICE
    assert calls == ["probe"]


@pytest.mark.asyncio
@pytest.mark.usefixtures("this_machine")
async def test_every_sandbox_names_the_process_that_owns_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    created: dict[str, Any] = {}

    def _create(**options: Any) -> Any:
        created.update(options)
        return types.SimpleNamespace(short_id="sandbox-1")

    daemon = types.SimpleNamespace(containers=types.SimpleNamespace(create=_create))
    client = docker_client.ZenDockerSandboxClient(daemon)
    monkeypatch.setattr(client, "image_exists", lambda _image: True)

    await client._create_container(_IMAGE)

    expected = {
        owner.OWNER_HOST_LABEL: _HOST,
        owner.OWNER_USER_LABEL: _USER,
        owner.OWNER_PID_LABEL: str(os.getpid()),
        owner.OWNER_STARTED_LABEL: _STARTED,
    }
    labels = created["labels"]
    assert {key: labels.get(key) for key in expected} == expected


@pytest.mark.usefixtures("this_machine")
def test_a_sandbox_whose_owner_has_exited_is_cut_then_removed_and_reported() -> None:
    events: list[str] = []
    orphan = _Container("orphan-1", _labels(pid=_DEAD_PID), ["bridge", "lab"], events)
    alive = _Container("sandbox-2", _labels(pid=_ALIVE_PID), ["bridge"], events)
    client = _SweepClient([orphan, alive], events)

    swept = docker_client.sweep_orphan_sandboxes(make_client=lambda: client)

    assert swept == [_swept("orphan-1", "running")]
    assert events == [
        "disconnect orphan-1 from bridge force=True",
        "disconnect orphan-1 from lab force=True",
        "remove orphan-1 force=True",
    ]
    assert client.listings == [
        {"all": True, "filters": {"label": owner.OWNER_PID_LABEL}, "ignore_removed": True}
    ]
    assert client.closed


@pytest.mark.usefixtures("this_machine")
@pytest.mark.parametrize(
    "labels",
    [
        pytest.param(_labels(pid=_DEAD_PID, host=_OTHER_HOST), id="another-machine"),
        pytest.param(_labels(pid=_DEAD_PID, user="1001"), id="another-user"),
        pytest.param(_labels(pid=""), id="no-owner-id"),
        pytest.param(_labels(pid=_ALIVE_PID), id="owner-alive"),
    ],
)
def test_a_sandbox_whose_owner_is_alive_or_cannot_be_told_is_never_touched(
    labels: dict[str, str],
) -> None:
    events: list[str] = []
    client = _SweepClient([_Container("sandbox-9", labels, ["bridge"], events)], events)

    assert docker_client.sweep_orphan_sandboxes(make_client=lambda: client) == []
    assert events == []
    assert client.closed


@pytest.mark.usefixtures("this_machine")
def test_a_stopped_sandbox_whose_owner_has_exited_is_removed_and_reported() -> None:
    events: list[str] = []
    held = _Container("orphan-2", _labels(pid=_DEAD_PID), ["bridge"], events, status="exited")
    client = _SweepClient([held], events)

    swept = docker_client.sweep_orphan_sandboxes(make_client=lambda: client)

    assert swept == [_swept("orphan-2", "exited")]
    assert events == ["disconnect orphan-2 from bridge force=True", "remove orphan-2 force=True"]


@pytest.mark.usefixtures("this_machine")
def test_a_stopped_sandbox_whose_owner_lives_is_never_touched() -> None:
    events: list[str] = []
    held = _Container("sandbox-3", _labels(pid=_ALIVE_PID), ["bridge"], events, status="exited")
    client = _SweepClient([held], events)

    assert docker_client.sweep_orphan_sandboxes(make_client=lambda: client) == []
    assert events == []


@pytest.mark.usefixtures("this_machine")
def test_a_paused_sandbox_whose_owner_has_exited_is_cut_then_removed() -> None:
    events: list[str] = []
    held = _Container("orphan-3", _labels(pid=_DEAD_PID), ["bridge"], events, status="paused")
    client = _SweepClient([held], events)

    swept = docker_client.sweep_orphan_sandboxes(make_client=lambda: client)

    assert swept == [_swept("orphan-3", "paused")]
    assert events == ["disconnect orphan-3 from bridge force=True", "remove orphan-3 force=True"]


@pytest.mark.usefixtures("this_machine")
def test_a_sandbox_the_daemon_is_already_removing_is_left_to_it() -> None:
    events: list[str] = []
    held = _Container("orphan-4", _labels(pid=_DEAD_PID), ["bridge"], events, status="removing")
    client = _SweepClient([held], events)

    assert docker_client.sweep_orphan_sandboxes(make_client=lambda: client) == []
    assert events == []


@pytest.mark.asyncio
async def test_a_start_removes_orphaned_sandboxes_first_and_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "sweep-first"
    order: list[str] = []

    def _sweep() -> list[dict[str, str]]:
        order.append("sweep")
        return [_swept("orphan-1", "running"), _swept("orphan-2", "exited")]

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        order.append("start")
        return _Client(), _Session()

    monkeypatch.setattr(docker_client, "sweep_orphan_sandboxes", _sweep)
    _use_docker_backend(monkeypatch, _backend)
    phases: list[str] = []
    try:
        bundle = await session_manager.create_or_reuse(
            scan_id, image=_IMAGE, local_sources=[], status_sink=phases.append
        )
        await bundle["caido_client"].aclose()
    finally:
        await session_manager.cleanup(scan_id)

    assert order == ["sweep", "start"]
    assert phases[0] == _SWEPT_MESSAGE


@pytest.mark.asyncio
async def test_a_start_arms_the_scans_stop_with_its_sandbox(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "start-arms"
    api = _Api(["bridge"])

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        return _CuttableClient(api), _Session()

    backend_name = f"test-{scan_id}"
    _use_backend(monkeypatch, backend_name, _backend, supports_bind_mounts=True)
    stop = stop_module.begin_scan_stop(scan_id)
    try:
        bundle = await session_manager.create_or_reuse(scan_id, image=_IMAGE, local_sources=[])
        await bundle["caido_client"].aclose()
        record = await stop_module.cut_sandbox_network(scan_id, "signal SIGTERM")
    finally:
        await session_manager.cleanup(scan_id)
        _forget_backend(backend_name)

    assert bundle["stop"] is stop
    assert record["cut_result"] == "cut"
    assert api.attached == []


@pytest.mark.asyncio
async def test_a_sandbox_whose_cut_cannot_be_armed_never_starts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "uncuttable"
    client = _UncuttableClient()
    session = _Session()

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        return client, session

    backend_name = f"test-{scan_id}"
    _use_backend(monkeypatch, backend_name, _backend, supports_bind_mounts=True)
    try:
        with pytest.raises(ConnectionError, match="did not describe"):
            await session_manager.create_or_reuse(scan_id, image=_IMAGE, local_sources=[])
    finally:
        await session_manager.cleanup(scan_id)
        _forget_backend(backend_name)

    assert client.deleted == [session]
    assert scan_id not in session_manager._SESSION_CACHE


@pytest.mark.asyncio
async def test_a_sandbox_whose_network_was_cut_is_never_reused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "cut-not-reused"
    clients: list[_CuttableClient] = []

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        clients.append(_CuttableClient(_Api(["bridge"])))
        return clients[-1], _Session()

    backend_name = f"test-{scan_id}"
    _use_backend(monkeypatch, backend_name, _backend, supports_bind_mounts=True)
    try:
        stop_module.begin_scan_stop(scan_id)
        first = await session_manager.create_or_reuse(scan_id, image=_IMAGE, local_sources=[])
        await stop_module.cut_sandbox_network(scan_id, "scan ended")
        cached_after_cut = scan_id in session_manager._SESSION_CACHE
        stop_module.begin_scan_stop(scan_id)
        second = await session_manager.create_or_reuse(scan_id, image=_IMAGE, local_sources=[])
        for bundle in (first, second):
            await bundle["caido_client"].aclose()
    finally:
        await session_manager.cleanup(scan_id)
        _forget_backend(backend_name)

    assert not cached_after_cut
    assert second is not first
    assert [client.deleted for client in clients] == [[first["session"]], [second["session"]]]
    assert clients[0].api.attached == []


@pytest.mark.asyncio
async def test_a_cached_sandbox_whose_cut_has_begun_is_never_handed_out(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    scan_id = "planted-cut"
    started: list[str] = []

    async def _backend(**_kwargs: Any) -> tuple[Any, Any]:
        started.append("a fresh sandbox")
        return _Client(), _Session()

    backend_name = f"test-{scan_id}"
    _use_backend(monkeypatch, backend_name, _backend, supports_bind_mounts=True)
    planted_client = _Client()
    planted = {
        "client": planted_client,
        "session": _Session(),
        "caido_client": None,
        "stop": types.SimpleNamespace(cut_started=True),
    }
    session_manager._SESSION_CACHE[scan_id] = planted
    try:
        bundle = await session_manager.create_or_reuse(scan_id, image=_IMAGE, local_sources=[])
        await bundle["caido_client"].aclose()
    finally:
        await session_manager.cleanup(scan_id)
        _forget_backend(backend_name)

    assert bundle is not planted
    assert started == ["a fresh sandbox"]
    assert planted_client.deleted == [planted["session"]]


def test_run_json_records_the_stop_and_the_report_header_states_the_cut_time(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "stop-record"
    stop_module.begin_scan_stop(scan_id).arm(_target(_Api(["bridge"])))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)

    record = stop_module.cut_sandbox_network_now(scan_id, "signal SIGTERM")
    state.final_scan_result = _REPORT
    state.save_run_data()

    run_dir = tmp_path / "zen_runs" / scan_id
    assert _run_json(run_dir)["stops"] == [record]
    assert record["reason"] == "signal SIGTERM"
    assert record["cut_result"] == "cut"
    assert _stopped_lines(run_dir) == [_stopped_line(record)]


def test_a_resumed_run_keeps_the_first_stop_and_records_its_own(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.chdir(tmp_path)
    scan_id = "resumed-stops"
    hold = threading.Event()
    first_stop = stop_module.begin_scan_stop(scan_id)
    first_stop.arm(_target(_Api(["bridge"], hold=hold)))
    state = ReportState(scan_id)
    monkeypatch.setattr(report_state_module, "_global_report_state", state)
    try:
        first_stop.request("signal SIGINT")
        while_cutting = stop_module._note(first_stop)
    finally:
        hold.set()
    assert first_stop.wait()
    first = stop_module._note(first_stop)

    assert while_cutting["cut_result"] == "not cut yet (the cut is still running)"
    assert state.run_record["stops"] == [first]

    # A start is told apart by when it began, to the millisecond.
    time.sleep(0.01)
    resumed = ReportState(scan_id)
    resumed.hydrate_from_run_dir()
    monkeypatch.setattr(report_state_module, "_global_report_state", resumed)
    stop_module.begin_scan_stop(scan_id).arm(_target(_Api(["bridge"])))
    second = stop_module.cut_sandbox_network_now(scan_id, "signal SIGTERM")
    resumed.final_scan_result = _REPORT
    resumed.save_run_data()

    run_dir = tmp_path / "zen_runs" / scan_id
    assert _run_json(run_dir)["stops"] == [first, second]
    assert _stopped_lines(run_dir) == [_stopped_line(first), _stopped_line(second)]


@pytest.mark.parametrize(
    ("ending", "escapes", "stops"),
    [
        pytest.param("cli-ended", None, [], id="cli-ended"),
        pytest.param("cli-stopped", SystemExit, [("signal SIGINT", _NOT_ARMED)], id="cli-stopped"),
        pytest.param("cli-failed", RuntimeError, [], id="cli-failed"),
        pytest.param("tui-stopped", SystemExit, [], id="tui-stopped"),
    ],
)
def test_a_sandbox_this_process_still_owns_when_main_ends_is_cut_removed_and_reported(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    exit_sweep_log: list[str],
    ending: str,
    escapes: type[BaseException] | None,
    stops: list[tuple[str, str]],
) -> None:
    run_name = f"own-{ending}"
    state = _main_ready(monkeypatch, tmp_path, run_name, interactive=ending.startswith("tui-"))
    events: list[str] = []
    daemon = _SweepClient([], events)
    monkeypatch.setattr(docker_client, "DEFAULT_SWEEP_CLIENT", lambda: daemon)
    printed: list[str] = []
    monkeypatch.setattr(main_module, "Console", lambda: _console(printed))

    async def _scan(_args: Any) -> None:
        stop_module.begin_scan_stop(run_name)
        await docker_client.ZenDockerSandboxClient(daemon)._create_container(_IMAGE)
        _end_scan(ending, run_name, state)

    _scan_with(monkeypatch, _scan)

    with pytest.raises(escapes) if escapes else contextlib.nullcontext():
        main_module.main()

    assert daemon.listings == [_own_listing()]
    assert events == [
        "disconnect sandbox-1 from bridge force=True",
        "remove sandbox-1 force=True",
    ]
    assert exit_sweep_log == [_LEFT_AT_EXIT]
    assert printed == [_REMOVED_AT_EXIT]
    # The exit sweep leaves run.json's record of the stop as the stop wrote it.
    run_json = _run_json(tmp_path / "zen_runs" / run_name)
    assert [(stop["reason"], stop["cut_result"]) for stop in run_json.get("stops", [])] == stops


@pytest.mark.usefixtures("this_machine")
def test_the_exit_sweep_never_touches_a_sandbox_of_another_live_owner(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_sweep_log: list[str]
) -> None:
    pid = str(os.getpid())
    events: list[str] = []
    # Three listed under this process's pid that name another start time, machine or user,
    # and one of another zen process that is alive, which the listing leaves out.
    others = [
        _Container("other-1", _labels(pid=pid, started="434343"), ["bridge"], events),
        _Container("other-2", _labels(pid=pid, host=_OTHER_HOST), ["bridge"], events),
        _Container("other-3", _labels(pid=pid, user="1001"), ["bridge"], events),
        _Container("other-4", _labels(pid=_ALIVE_PID), ["bridge"], events),
    ]
    daemon = _SweepClient(others, events)
    monkeypatch.setattr(docker_client, "DEFAULT_SWEEP_CLIENT", lambda: daemon)
    _main_ready(monkeypatch, tmp_path, "other-owners")
    _scan_with(monkeypatch, _scan_torn_down(daemon))

    main_module.main()

    assert daemon.listings == [_own_listing()]
    assert events == ["remove sandbox-5 force=True"]
    assert exit_sweep_log == []


def test_a_sandbox_teardown_removed_costs_the_exit_sweep_one_listing_and_nothing_else(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_sweep_log: list[str]
) -> None:
    events: list[str] = []
    daemon = _SweepClient([], events)
    monkeypatch.setattr(docker_client, "DEFAULT_SWEEP_CLIENT", lambda: daemon)
    _main_ready(monkeypatch, tmp_path, "torn-down")
    printed: list[str] = []
    monkeypatch.setattr(main_module, "Console", lambda: _console(printed))
    _scan_with(monkeypatch, _scan_torn_down(daemon))

    main_module.main()

    assert daemon.listings == [_own_listing()]
    assert events == ["remove sandbox-1 force=True"]
    assert exit_sweep_log == []
    assert printed == []
    assert daemon.closed


def test_when_no_sandbox_was_created_main_asks_the_docker_daemon_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    made: list[str] = []

    def _sweep_client() -> _SweepClient:
        made.append("sweep client")
        return _SweepClient([], [])

    monkeypatch.setattr(docker_client, "DEFAULT_SWEEP_CLIENT", _sweep_client)
    _main_ready(monkeypatch, tmp_path, "no-sandbox")
    _scan_with(monkeypatch, _no_scan)

    main_module.main()

    assert made == []


@pytest.mark.usefixtures("stop_signal_handlers_restored")
def test_a_stop_signal_while_main_finishes_only_says_the_stop_is_under_way(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, exit_sweep_log: list[str]
) -> None:
    run_name = "finishing"
    state = _main_ready(monkeypatch, tmp_path, run_name)
    events: list[str] = []
    daemon = _SweepClient([], events)
    monkeypatch.setattr(docker_client, "DEFAULT_SWEEP_CLIENT", lambda: daemon)
    printed: list[str] = []
    monkeypatch.setattr(main_module, "Console", lambda: _console(printed))
    # One stop signal while the exit sweep lists, one while the run record is last saved.
    pending = [signal.SIGINT, signal.SIGTERM]
    listed = daemon.containers.list
    record_run = state.cleanup

    def _signal_once() -> None:
        if pending:
            os.kill(os.getpid(), pending.pop(0))

    def _list(**options: Any) -> list[_Container]:
        _signal_once()
        return listed(**options)

    def _cleanup(status: str = "stopped") -> None:
        _signal_once()
        record_run(status)

    monkeypatch.setattr(daemon.containers, "list", _list)
    monkeypatch.setattr(state, "cleanup", _cleanup)
    bound: list[Any] = []

    async def _scan(_args: Any) -> None:
        # As run_cli does, the command line's stop handler is bound first; then the scan
        # fails on its own after its sandbox was made, so no stop is ever requested.
        stop_module.begin_scan_stop(run_name)
        bound.append(cli._stop_signal_handler(run_name, state, _console(printed)))
        cli._install_stop_handlers(bound[0])
        await docker_client.ZenDockerSandboxClient(daemon)._create_container(_IMAGE)
        raise RuntimeError("the sandbox's bring-up failed")

    _scan_with(monkeypatch, _scan)

    with pytest.raises(RuntimeError, match="bring-up failed"):
        main_module.main()

    assert printed == [stop_module.STOP_UNDER_WAY, _REMOVED_AT_EXIT, stop_module.STOP_UNDER_WAY]
    assert events == [
        "disconnect sandbox-1 from bridge force=True",
        "remove sandbox-1 force=True",
    ]
    assert exit_sweep_log == [_LEFT_AT_EXIT]
    run_json = _run_json(tmp_path / "zen_runs" / run_name)
    assert run_json["status"] == "failed"
    assert run_json.get("stops", []) == []
    handlers = {signum: signal.getsignal(signum) for signum in _STOP_SIGNALS}
    assert handlers == dict.fromkeys(_STOP_SIGNALS, bound[0])


@pytest.mark.usefixtures("stop_signal_handlers_restored")
def test_a_stop_signal_after_mains_last_save_leaves_the_run_record_as_saved(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    run_name = "late-signal"
    state = _main_ready(monkeypatch, tmp_path, run_name)
    printed: list[str] = []

    def _beacon(*_args: Any, **_kwargs: Any) -> None:
        os.kill(os.getpid(), signal.SIGINT)

    monkeypatch.setattr(main_module.posthog, "end", _beacon)

    async def _scan(_args: Any) -> None:
        # As run_cli does, the command line's stop handler is bound first; then bring-up
        # fails on its own, so no stop is ever requested.
        stop_module.begin_scan_stop(run_name)
        cli._install_stop_handlers(cli._stop_signal_handler(run_name, state, _console(printed)))
        raise RuntimeError("the sandbox's bring-up failed")

    _scan_with(monkeypatch, _scan)

    with pytest.raises(RuntimeError, match="bring-up failed"):
        main_module.main()

    run_json = _run_json(tmp_path / "zen_runs" / run_name)
    assert run_json["status"] == "failed"
    assert run_json.get("stops", []) == []
    assert printed == [stop_module.STOP_UNDER_WAY]
