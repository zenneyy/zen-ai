"""Shared test fixtures."""

from __future__ import annotations

import os

import pytest


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
