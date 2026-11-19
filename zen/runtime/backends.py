"""Sandbox backend registry — selected via ZEN_RUNTIME_BACKEND (default: docker)."""

from __future__ import annotations

import logging
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Any, cast


if TYPE_CHECKING:
    from agents.sandbox.manifest import Manifest

    from zen.runtime.stop import CutTarget


logger = logging.getLogger(__name__)


SandboxBackend = Callable[..., Awaitable[tuple[Any, Any]]]


async def _docker_backend(
    *,
    image: str,
    manifest: Manifest,
    exposed_ports: tuple[int, ...],
    bind_mounts: list[dict[str, Any]] | None = None,
) -> tuple[Any, Any]:
    """Bring up a session backed by the local Docker daemon.

    Uses :class:`ZenDockerSandboxClient` to inject NET_ADMIN /
    NET_RAW caps + ``host.docker.internal`` host-gateway. Imports
    ``docker`` lazily so deployments that target a non-Docker
    backend don't need the docker-py library installed.

    ``session.start()`` is what materializes the manifest into the running
    container — the SDK's ``client.create()`` only builds the inner session
    object without applying it. ``async with session:`` would call it too, but
    Zen manages session lifetime explicitly via ``client.delete()`` so we
    trigger ``start()`` ourselves.
    """
    import docker
    from agents.sandbox.sandboxes.docker import DockerSandboxClientOptions

    from zen.runtime.docker_client import ZenDockerSandboxClient, docker_connection

    # One connection: the scan's client is made from it and keeps it, so that the cut a
    # stop makes reaches the same daemon.
    connection = docker_connection()
    client = ZenDockerSandboxClient(docker.DockerClient(**connection))
    client.zen_connection = connection
    client.zen_bind_mounts = bind_mounts or []
    options = DockerSandboxClientOptions(image=image, exposed_ports=exposed_ports)
    session = await client.create(options=options, manifest=manifest)
    await session.start()
    return client, session


_BACKENDS: dict[str, SandboxBackend] = {
    "docker": _docker_backend,
}

_BIND_MOUNT_BACKENDS: set[str] = {"docker"}


def get_backend(name: str) -> SandboxBackend:
    """Return the backend factory for ``name`` or raise.

    Args:
        name: Backend identifier (e.g. ``"docker"``). Match is exact;
            no fallback. Unknown values raise so config typos surface
            immediately instead of silently picking a default.
    """
    backend = _BACKENDS.get(name)
    if backend is None:
        supported = ", ".join(sorted(_BACKENDS))
        raise ValueError(
            f"Unknown ZEN_RUNTIME_BACKEND: {name!r} (supported: {supported})",
        )
    logger.debug("Selected sandbox backend: %s", name)
    return backend


def register_backend(
    name: str,
    backend: SandboxBackend,
    *,
    supports_bind_mounts: bool = False,
) -> None:
    """Register a custom backend under ``name``.

    Intended for downstream users who ship their own runtime — register
    before any ``session_manager.create_or_reuse`` call. Re-registering
    an existing name overwrites the prior entry. ``supports_bind_mounts``
    defaults to False: a remote runtime cannot see the caller's filesystem, so
    it is handed local sources as manifest entries to upload instead.
    """
    _BACKENDS[name] = backend
    if supports_bind_mounts:
        _BIND_MOUNT_BACKENDS.add(name)
    else:
        _BIND_MOUNT_BACKENDS.discard(name)
    logger.info("Registered sandbox backend: %s (bind mounts: %s)", name, supports_bind_mounts)


def backend_supports_bind_mounts(name: str) -> bool:
    return name in _BIND_MOUNT_BACKENDS


def supported_backends() -> list[str]:
    return sorted(_BACKENDS)


def sweep_orphans(name: str) -> list[dict[str, str]]:
    """Cut and remove the sandboxes that a zen process which has exited left running.

    Only the Docker backend labels its sandboxes with their owner; another backend has
    nothing to sweep here.
    """
    if name != "docker":
        return []
    from zen.runtime.docker_client import sweep_orphan_sandboxes

    return sweep_orphan_sandboxes()


def network_cut_target(client: Any, session: Any) -> CutTarget | None:
    """What a scan's stop needs to cut this sandbox's network, or None when the backend
    offers no cut."""
    make_target = getattr(client, "network_cut_target", None)
    if make_target is None:
        return None
    return cast("CutTarget", make_target(session))
