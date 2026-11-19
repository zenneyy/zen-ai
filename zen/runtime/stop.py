"""Stop means stop: when a scan stops, its sandbox loses its network first.

Every start of a scan has one :class:`ScanStop`. It is armed with the sandbox once the
sandbox is up, and it receives the stop from whichever path ends the scan first: the
runner's own end, a stop signal or the TUI. The first stop starts the cut on a thread of
its own, with a Docker client of its own and a hard deadline, so the cut never waits on
the event loop, on the agents or on the scan's Docker client; a later stop neither repeats
nor skips it. The cut detaches the sandbox from every network, confirms that none is
left, and kills the sandbox when that cannot be confirmed. Once the stop is received,
every tool an agent holds answers with :data:`STOP_NOTICE` instead of running.

A sandbox whose network was cut is never handed out again (see ``session_manager``), and
each start's stop is recorded in run.json and in the report header.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Any, Final

from zen.report.state import get_global_report_state


if TYPE_CHECKING:
    from collections.abc import Callable, Mapping


logger = logging.getLogger(__name__)

CUT_REQUEST_TIMEOUT_S: Final = 1.0
CUT_DEADLINE_S: Final = 3.0
STOP_CONTEXT_KEY: Final = "scan_stop"
STOP_NOTICE: Final = (
    "Stop received: this scan is ending and its sandbox's network is cut, so this tool "
    "call did not run. Do not retry it."
)
# The exit status of a scan a stop signal ended, on the command line and in the TUI alike.
STOP_EXIT_STATUS: Final = 1
# What a further stop signal is told while the first stop's path runs to the end. It holds
# whenever it can be printed, the cut still running included.
STOP_UNDER_WAY: Final = (
    "Stop already under way: zen exits once the cleanup is done; SIGKILL abandons the cleanup."
)

_CUT: Final = "cut"
_GONE: Final = "cut (the sandbox was already gone)"
_RUNNING: Final = "not cut yet (the cut is still running)"
_NOT_ARMED: Final = "not cut (no sandbox network was armed)"
_NOT_FOUND: Final = 404


@dataclass(frozen=True)
class CutTarget:
    """What a cut needs: a Docker client of its own, the container, and the networks the
    container was attached to when the stop was armed."""

    client: Any
    container_id: str
    networks: tuple[str, ...]


class CutError(RuntimeError):
    """The sandbox is still attached to a network after its disconnects."""


class ScanStop:
    """The stop of one start of a scan."""

    def __init__(self, scan_id: str) -> None:
        self.scan_id = scan_id
        self.started_at = _now()
        self.reason: str | None = None
        self.received_at: str | None = None
        self.cut_at: str | None = None
        self.cut_result: str | None = None
        self._target: CutTarget | None = None
        self._on_cut: Callable[[], None] | None = None
        self._thread: threading.Thread | None = None
        self._run_ended = False
        # Reentrant: a signal handler can run on the main thread while it holds the lock.
        self._lock = threading.RLock()

    @property
    def requested(self) -> bool:
        """Whether the stop has been received."""
        return self.reason is not None

    @property
    def run_ended(self) -> bool:
        """Whether the run has ended: its record has had its last save, which no stop that
        comes later changes."""
        return self._run_ended

    def note_run_ended(self) -> None:
        """Note that the run's record has had its last save."""
        self._run_ended = True

    @property
    def cut_started(self) -> bool:
        """Whether the cut of the armed sandbox has begun."""
        return self._thread is not None

    def arm(self, target: CutTarget, on_cut: Callable[[], None] | None = None) -> None:
        """Hand the stop the sandbox to cut. A stop received earlier cuts it now.

        ``on_cut`` runs once, when the cut begins.
        """
        with self._lock:
            self._target = target
            self._on_cut = on_cut
        self._start_cut()

    def request(self, reason: str) -> None:
        """Receive the stop. The first reason and time are kept, and the cut starts as
        soon as a sandbox is armed, once."""
        with self._lock:
            if self.reason is None:
                self.reason = reason
                self.received_at = _now()
                logger.info("Stop received for scan %s: %s", self.scan_id, reason)
        self._start_cut()

    def wait(self, timeout: float = CUT_DEADLINE_S) -> bool:
        """Wait at most ``timeout`` seconds for the cut; True once it is not running."""
        thread = self._thread
        if thread is None:
            return True
        thread.join(timeout)
        return not thread.is_alive()

    def record(self) -> dict[str, str | None]:
        """This start's stop, as run.json records it."""
        with self._lock:
            if self.cut_result is not None:
                cut_result: str | None = self.cut_result
            elif self._thread is not None:
                cut_result = _RUNNING
            elif self._target is None:
                cut_result = _NOT_ARMED
            else:
                cut_result = None
            return {
                "started_at": self.started_at,
                "reason": self.reason,
                "received_at": self.received_at,
                "cut_at": self.cut_at,
                "cut_result": cut_result,
            }

    def _start_cut(self) -> None:
        with self._lock:
            if self._thread is not None or self._target is None or self.reason is None:
                return
            # Not a daemon: an exiting interpreter waits for the cut instead of dropping it.
            self._thread = threading.Thread(
                target=self._cut,
                args=(self._target,),
                name=f"zen-network-cut-{self.scan_id}",
                daemon=False,
            )
            self._thread.start()
            on_cut = self._on_cut
        if on_cut is not None:
            with contextlib.suppress(Exception):
                on_cut()

    def _cut(self, target: CutTarget) -> None:
        deadline = time.monotonic() + CUT_DEADLINE_S
        try:
            result = _disconnect(target, deadline)
        except Exception as exc:  # noqa: BLE001 - a cut records its failure and never raises
            result = _kill(target, deadline, exc)
        with contextlib.suppress(Exception):
            target.client.close()
        with self._lock:
            self.cut_result = result
            self.cut_at = _now()
        log = logger.warning if result.startswith("not cut") else logger.info
        log("Sandbox network of scan %s: %s", self.scan_id, result)


_STOPS: dict[str, ScanStop] = {}
# Reentrant for the same reason as a stop's own lock.
_STOPS_LOCK = threading.RLock()


def begin_scan_stop(scan_id: str) -> ScanStop:
    """Give a new start of ``scan_id`` a stop of its own; an earlier start's is dropped."""
    stop = ScanStop(scan_id)
    with _STOPS_LOCK:
        _STOPS[scan_id] = stop
    return stop


def scan_stop(scan_id: str) -> ScanStop:
    """The stop of the current start of ``scan_id``, made on first use."""
    with _STOPS_LOCK:
        stop = _STOPS.get(scan_id)
        if stop is None:
            stop = _STOPS[scan_id] = ScanStop(scan_id)
        return stop


async def cut_sandbox_network(scan_id: str, reason: str) -> dict[str, str | None]:
    """Receive the stop of ``scan_id`` and wait, off the event loop, for its sandbox's
    network to be cut. Returns the stop's record, which run.json also gets."""
    stop = scan_stop(scan_id)
    stop.request(reason)
    await asyncio.to_thread(stop.wait)
    return _note(stop)


def cut_sandbox_network_now(scan_id: str, reason: str) -> dict[str, str | None]:
    """:func:`cut_sandbox_network` for a synchronous caller, such as a signal handler."""
    stop = scan_stop(scan_id)
    stop.request(reason)
    stop.wait()
    return _note(stop)


def stop_notice(context: Any) -> str | None:
    """What a tool returns instead of running, once its scan's stop was received."""
    if not isinstance(context, dict):
        return None
    if getattr(context.get(STOP_CONTEXT_KEY), "requested", False) is True:
        return STOP_NOTICE
    return None


def stop_acknowledgment(record: Mapping[str, Any]) -> str:
    """One line for the operator once a stop signal has been handled."""
    cut_at = record.get("cut_at")
    when = f" at {cut_at}" if cut_at else ""
    return (
        f"Stop received ({record.get('reason')}): sandbox network "
        f"{record.get('cut_result') or 'not cut'}{when}. Stopping the agents."
    )


def _note(stop: ScanStop) -> dict[str, str | None]:
    """Record the stop in its scan's run.json, when this process writes that run."""
    record = stop.record()
    report_state = get_global_report_state()
    if report_state is None or (report_state.run_name or report_state.run_id) != stop.scan_id:
        return record
    try:
        report_state.record_stop(record)
    except Exception:
        logger.exception("Could not record the stop of scan %s in run.json", stop.scan_id)
    return record


def _disconnect(target: CutTarget, deadline: float) -> str:
    """Detach the sandbox from every network, then confirm that none is left."""
    api = target.client.api
    for network in target.networks:
        _detach(api, target.container_id, network, deadline)
    attached = _attached(api, target.container_id, deadline)
    if attached is None:
        return _GONE
    if not attached:
        return _CUT
    # Networks attached after the stop was armed: cut those too, then look once more.
    for network in attached:
        _detach(api, target.container_id, network, deadline)
    left = _attached(api, target.container_id, deadline)
    if left is None:
        return _GONE
    if left:
        raise CutError(f"still attached to {', '.join(left)}")
    return _CUT


def _detach(api: Any, container_id: str, network: str, deadline: float) -> None:
    _in_time(deadline)
    # A disconnect that fails is caught by the look that follows it.
    with contextlib.suppress(Exception):
        api.disconnect_container_from_network(container_id, network, force=True)


def _attached(api: Any, container_id: str, deadline: float) -> list[str] | None:
    """The networks the sandbox is attached to now; None once it no longer exists."""
    _in_time(deadline)
    try:
        attrs = api.inspect_container(container_id)
    except Exception as exc:
        if _gone(exc):
            return None
        raise
    networks = (attrs.get("NetworkSettings") or {}).get("Networks") or {}
    return sorted(networks)


def _kill(target: CutTarget, deadline: float, cause: Exception) -> str:
    """End a sandbox whose disconnect cannot be confirmed: a killed sandbox has no network."""
    try:
        _in_time(deadline)
        target.client.api.kill(target.container_id)
    except Exception as exc:  # noqa: BLE001 - a cut records its failure and never raises
        if _gone(exc):
            return _GONE
        return f"not cut ({_describe(cause)}, then {_describe(exc)})"
    return f"cut by killing the sandbox (the disconnect failed: {_describe(cause)})"


def _in_time(deadline: float) -> None:
    if time.monotonic() + CUT_REQUEST_TIMEOUT_S > deadline:
        raise TimeoutError("the cut's deadline has passed")


def _gone(exc: BaseException) -> bool:
    return getattr(exc, "status_code", None) == _NOT_FOUND


def _describe(exc: BaseException) -> str:
    text = str(exc).strip()
    return f"{type(exc).__name__}: {text}" if text else type(exc).__name__


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="milliseconds")
