"""Shared test fixtures."""

from __future__ import annotations

import os
from typing import TYPE_CHECKING, NoReturn

import pytest

from zen.core import provenance
from zen.tools.ledger.runtime import set_ledger


if TYPE_CHECKING:
    from collections.abc import Iterator


# Ambient configuration surface the settings models read from the environment.
# A developer shell -- or the Zen bridge runtime -- that exports any of these
# would otherwise leak into tests that construct settings without setting the
# key themselves. Cleared before every test; a test that needs a value sets it
# with its own monkeypatch, which runs after this fixture.
_ISOLATED_ENV_PREFIXES = ("ZEN_", "LLM_", "DEDUPE_", "OPENAI_")
_ISOLATED_ENV_NAMES = (
    "MODEL",
    "REASONING",
    "PERPLEXITY_API_KEY",
    "EXA_API_KEY",
    "DEEPSEEK_API_KEY",
    "POSTMAN_API_KEY",
)


@pytest.fixture(autouse=True)
def _isolate_mcp_config(
    monkeypatch: pytest.MonkeyPatch, tmp_path_factory: pytest.TempPathFactory
) -> None:
    """Keep the suite from reading the developer's real environment.

    Two kinds of leakage matter. ``run_zen_scan`` connects the MCP servers
    listed in ``~/.zen/mcp-servers.json`` and threads an inventory of them into
    the prompt context, so without isolation any test that drives the runner on
    a machine with a real config would do real network I/O. And the settings
    models read model/provider configuration straight from the environment, so
    an exported ``ZEN_LLM``, ``ZEN_REASONING_EFFORT``, ``OPENAI_API_BASE`` and
    the like would leak into tests that build settings without setting those
    keys. Clear both surfaces here; tests that exercise them set their own
    values afterwards and so override this.
    """
    for name in list(os.environ):
        if name == "ZEN_MCP_CONFIG":
            continue
        if name.startswith(_ISOLATED_ENV_PREFIXES) or name in _ISOLATED_ENV_NAMES:
            monkeypatch.delenv(name, raising=False)

    missing = tmp_path_factory.mktemp("mcp-isolation") / "no-servers.json"
    monkeypatch.setenv("ZEN_MCP_CONFIG", str(missing))
    monkeypatch.delenv("ZEN_MCP_ONLY", raising=False)
    monkeypatch.delenv("ZEN_MCP_EXCLUDE", raising=False)


@pytest.fixture(autouse=True)
def _plain_terminal(monkeypatch: pytest.MonkeyPatch) -> None:
    """Make Rich output identical on every developer's machine.

    Many CLI tests force ``isatty()`` to ``True`` to exercise the human-readable
    code path and then assert on the plain text. Rich picks its color system
    from ``TERM``, ``COLORTERM``, and ``FORCE_COLOR``, so on a real terminal
    those assertions would meet ANSI escape codes instead of the words they
    look for. A dumb terminal renders the same text without any styling.
    """
    monkeypatch.setenv("TERM", "dumb")
    for name in ("COLORTERM", "FORCE_COLOR", "NO_COLOR", "TTY_COMPATIBLE"):
        monkeypatch.delenv(name, raising=False)


@pytest.fixture(autouse=True)
def _isolate_research_ledger() -> Iterator[None]:
    """Detach the run-scoped research ledger (2.1) around every test.

    The ledger is a process-global installed per run. A test that drives the
    runner installs one; a test that exercises a tool in isolation installs none
    and must see the dict-backed fallback paths. Detaching before and after each
    test keeps a ledger from one test leaking into the gates of the next — the
    tool/gate code treats "no ledger" as "use the dict store", so an isolated
    tool test is unaffected, and a test that wants the object-backed path
    installs its own ledger after this fixture has cleared the slate.
    """
    set_ledger(None)
    try:
        yield
    finally:
        set_ledger(None)


def _no_health_reply(url: str) -> NoReturn:
    raise ConnectionRefusedError(f"no endpoint is asked during tests: {url}")


@pytest.fixture
def production_provenance_defaults() -> None:
    """Requested by a test that must see provenance's defaults as a scan does; the
    isolation fixture below then leaves them alone."""


@pytest.fixture(autouse=True)
def _isolate_run_provenance(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Keep a scan a test starts from reading the developer's checkout or endpoint.

    Run provenance reads the git checkout zen is imported from and asks a local
    model endpoint for its health reply. Every test gets a package path that is
    not a checkout and a health reply that never connects; a test about
    provenance sets its own after this fixture, and a test that requests
    ``production_provenance_defaults`` keeps the defaults a scan uses. The runner's
    own reference to provenance is never replaced, here or in any test.
    """
    if "production_provenance_defaults" in request.fixturenames:
        return
    monkeypatch.setattr(
        provenance, "DEFAULT_PACKAGE_DIR", tmp_path_factory.getbasetemp() / "no-checkout" / "zen"
    )
    monkeypatch.setattr(provenance, "DEFAULT_FETCH_HEALTH", _no_health_reply)
