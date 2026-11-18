"""Which zen process owns a sandbox, so a later start can tell an orphan from a sandbox
another scan still uses.

Every sandbox is labelled with its owner's host identity (on Linux the boot id and the pid
namespace, so a pid means the same process to every reader of the label), user id, pid
and process start time (so a pid that was reused is not taken for the owner). A sandbox
counts as orphaned only when its host and user match this machine and user and its owner
is known to have exited. Anything that cannot be told is left alone.
"""

from __future__ import annotations

import os
import platform
from pathlib import Path
from typing import TYPE_CHECKING, Final


if TYPE_CHECKING:
    from collections.abc import Mapping


OWNER_HOST_LABEL: Final = "zen-owner-host"
OWNER_USER_LABEL: Final = "zen-owner-user"
OWNER_PID_LABEL: Final = "zen-owner-pid"
OWNER_STARTED_LABEL: Final = "zen-owner-started"

# What the sweep reports for an orphan whose networks were cut before it was removed.
ORPHAN_SWEPT: Final = "cut and removed"

_BOOT_ID: Final = Path("/proc/sys/kernel/random/boot_id")
_PID_NAMESPACE: Final = Path("/proc/self/ns/pid")
_PROC: Final = Path("/proc")
# Field 22 of /proc/<pid>/stat (the start time), counted from the field after the command.
_STARTTIME_INDEX: Final = 19


def host_identity() -> str:
    """This machine's boot and pid namespace, or its host name where /proc is absent."""
    try:
        boot_id = _BOOT_ID.read_text(encoding="ascii").strip()
        namespace = str(_PID_NAMESPACE.readlink())
    except OSError:
        return platform.node()
    return f"{boot_id}/{namespace}"


def user_identity() -> str:
    """The numeric user id, where the platform has one."""
    getuid = getattr(os, "getuid", None)
    return str(getuid()) if getuid is not None else ""


def process_started(pid: int) -> str | None:
    """When process ``pid`` started, in clock ticks since boot; None when there is no such
    process or /proc cannot be read."""
    try:
        stat = (_PROC / str(pid) / "stat").read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    # The command name sits in parentheses and may itself hold spaces or parentheses.
    fields = stat.rpartition(")")[2].split()
    if len(fields) <= _STARTTIME_INDEX:
        return None
    return fields[_STARTTIME_INDEX]


def owner_labels() -> dict[str, str]:
    """The labels that name this process as a sandbox's owner."""
    pid = os.getpid()
    return {
        OWNER_HOST_LABEL: host_identity(),
        OWNER_USER_LABEL: user_identity(),
        OWNER_PID_LABEL: str(pid),
        OWNER_STARTED_LABEL: process_started(pid) or "",
    }


def owner_gone(labels: Mapping[str, str]) -> bool:
    """True only when the zen process these labels name is known to have exited.

    A sandbox from another machine or another user, or one with no owner id, is never
    counted: whether its owner is alive cannot be told from here.
    """
    if labels.get(OWNER_HOST_LABEL) != host_identity():
        return False
    if labels.get(OWNER_USER_LABEL) != user_identity():
        return False
    try:
        pid = int(labels.get(OWNER_PID_LABEL) or "")
    except ValueError:
        return False
    if pid <= 0:
        return False
    started = labels.get(OWNER_STARTED_LABEL)
    if started:
        # Another process may hold the pid now; the start time tells the two apart.
        return process_started(pid) != started
    return _no_such_process(pid)


def _no_such_process(pid: int) -> bool:
    """Whether no process has ``pid``. A process that exists but is not ours counts as
    alive, and so does anything this platform cannot answer."""
    if os.name != "posix":
        # Elsewhere a signal 0 does not probe a process: it ends it.
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return True
    except OSError:
        return False
    return False
