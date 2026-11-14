"""What a Claude Code bridge session is allowed to reach.

Scope: the options the bridge starts a session with, the command line the Agent
SDK builds from them, the bridge's reading of the session's own account of
itself, and the gate on tool calls -- with a stand-in for the Agent SDK client.
Whether the Claude Code CLI honours each flag is not exercised here.
"""

from __future__ import annotations

import asyncio
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, override

import claude_agent_sdk
import pytest
from agents import Agent, ModelSettings, RunConfig
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run_internal import model_retry
from claude_agent_sdk import AssistantMessage, ResultMessage, SystemMessage, TextBlock
from claude_agent_sdk._internal.transport.subprocess_cli import SubprocessCLITransport
from openai import AsyncOpenAI, OpenAI, PermissionDeniedError

from zen.bridge import claude_code as bridge
from zen.config.models import DEFAULT_MODEL_RETRY
from zen.core import execution
from zen.core.agents import AgentCoordinator


if TYPE_CHECKING:
    from collections.abc import Iterator


_OPENING = [{"role": "user", "content": "hello"}]
_TOOLS = [
    {
        "type": "function",
        "function": {
            "name": "lookup",
            "description": "Look something up.",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]
_FOREIGN = "mcp__rea__binary_session"


def _reply(text: str) -> tuple[Any, ...]:
    return (
        AssistantMessage(content=[TextBlock(text=text)], model="m"),
        ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=0,
            is_error=False,
            num_turns=1,
            session_id="session",
        ),
    )


def _as_asked(options: Any) -> dict[str, Any]:
    """The account Claude Code gives of a session that holds what the bridge asked for."""
    return {
        "tools": list(options.allowed_tools),
        "mcp_servers": [{"name": name, "status": "connected"} for name in options.mcp_servers],
        "plugins": [],
        "skills": [],
        "slash_commands": [],
        "cwd": options.cwd,
        "permissionMode": options.permission_mode,
    }


def _with(**changes: Any) -> Any:
    """An account that differs from what was asked for in the given parts."""

    def told(options: Any) -> dict[str, Any]:
        account = _as_asked(options)
        for part, more in changes.items():
            account[part] = [*account[part], *more] if isinstance(more, list) else more
        return account

    return told


class _Sdk:
    """Stands in for the Agent SDK client: keeps the options it was started with and
    replays one scripted turn, led by whatever account of the session the test sets."""

    started: ClassVar[list[Any]] = []
    account: ClassVar[Any] = None
    script: ClassVar[tuple[Any, ...]] = ()
    queries: ClassVar[int] = 0

    def __init__(self, options: Any = None) -> None:
        self.options = options
        type(self).started.append(options)

    async def connect(self) -> None:
        """Nothing to start."""

    async def query(self, _prompt: Any) -> None:
        type(self).queries += 1

    async def receive_response(self) -> Any:
        told = type(self).account
        if told is not None:
            yield SystemMessage(subtype="init", data=told(self.options))
        for message in type(self).script:
            yield message

    async def disconnect(self) -> None:
        """Nothing to stop."""


class _Counted(bridge._Handler):
    posts: ClassVar[list[int]] = []

    @override
    def do_POST(self) -> None:
        type(self).posts.append(1)
        super().do_POST()


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> type[_Sdk]:
    monkeypatch.setattr(_Sdk, "started", [])
    monkeypatch.setattr(_Sdk, "account", _as_asked)
    monkeypatch.setattr(_Sdk, "script", _reply("hi"))
    monkeypatch.setattr(_Sdk, "queries", 0)
    monkeypatch.setattr(_Counted, "posts", [])
    monkeypatch.setattr(claude_agent_sdk, "ClaudeSDKClient", _Sdk)
    return _Sdk


@pytest.fixture
def bridge_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Counted)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        bridge._POOL.close_all()
        server.shutdown()
        server.server_close()


def _ask(base_url: str, messages: list[dict[str, Any]]) -> Any:
    with OpenAI(api_key="unused", base_url=base_url, max_retries=0, timeout=30.0) as client:
        reply = client.chat.completions.create(model="m", messages=messages, tools=_TOOLS)
    return reply.choices[0].message


def _command(options: Any) -> list[str]:
    """The command line the Agent SDK starts Claude Code with for these options."""
    transport = SubprocessCLITransport(prompt="", options=options)
    transport._cli_path = "claude"
    return transport._build_command()


def test_a_session_is_started_with_none_of_the_operators_setup(
    bridge_url: str, sdk: type[_Sdk]
) -> None:
    _ask(bridge_url, _OPENING)
    options = sdk.started[0]

    assert options.setting_sources == []
    assert options.strict_mcp_config is True
    assert list(options.mcp_servers) == ["zen"]
    assert options.tools == []
    assert options.skills == []
    assert options.extra_args == {"disable-slash-commands": None}
    assert options.permission_mode == "dontAsk"
    assert options.allowed_tools == ["mcp__zen__lookup"]
    assert options.env["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] == "1"
    assert options.env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
    assert options.env["ENABLE_CLAUDEAI_MCP_SERVERS"] == "false"
    assert len(options.hooks["PreToolUse"]) == 1


def test_the_command_line_for_a_session_carries_each_restriction(
    bridge_url: str, sdk: type[_Sdk]
) -> None:
    _ask(bridge_url, _OPENING)
    command = _command(sdk.started[0])

    assert "--strict-mcp-config" in command
    assert "--setting-sources=" in command
    assert "--disable-slash-commands" in command
    assert command[command.index("--tools") + 1] == ""
    assert command[command.index("--permission-mode") + 1] == "dontAsk"
    assert command[command.index("--allowedTools") + 1] == "mcp__zen__lookup"


def test_sessions_run_in_an_empty_directory_of_the_bridges_own(
    bridge_url: str, sdk: type[_Sdk]
) -> None:
    _ask(bridge_url, _OPENING)
    home = Path(sdk.started[0].cwd).resolve()
    here = Path.cwd().resolve()

    assert home.is_dir()
    assert list(home.iterdir()) == []
    assert home != here
    assert here not in home.parents
    assert home not in here.parents


@pytest.mark.usefixtures("sdk")
def test_a_session_that_reports_only_zens_tools_is_served_and_its_holdings_are_logged(
    bridge_url: str, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level("INFO", logger="zen.bridge.claude_code")

    assert _ask(bridge_url, _OPENING).content == "hi"
    assert "holds only zen's tools: tools ['mcp__zen__lookup']" in caplog.text


@pytest.mark.parametrize(
    ("account", "named"),
    [
        (_with(tools=[_FOREIGN]), _FOREIGN),
        (_with(tools=["Bash"]), "Bash"),
        (_with(mcp_servers=[{"name": "rea", "status": "connected"}]), "rea"),
        (_with(plugins=[{"name": "easel"}]), "easel"),
        (_with(skills=["reverse-engineer-anything"]), "reverse-engineer-anything"),
        (_with(slash_commands=["compact"]), "compact"),
        (_with(permissionMode="bypassPermissions"), "bypassPermissions"),
        (_with(cwd="/somewhere/else"), "/somewhere/else"),
    ],
)
def test_a_session_that_reports_more_than_zens_tools_is_refused(
    bridge_url: str,
    sdk: type[_Sdk],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    account: Any,
    named: str,
) -> None:
    monkeypatch.setattr(sdk, "account", account)

    with pytest.raises(PermissionDeniedError) as caught:
        _ask(bridge_url, _OPENING)

    assert caught.value.status_code == 403
    assert caught.value.type == "bridge_error"
    assert caught.value.code == "session_not_isolated"
    assert named in str(caught.value)
    assert named in caplog.text
    assert bridge._POOL._sessions == {}


def test_a_session_that_does_not_report_what_it_holds_is_refused(
    bridge_url: str, sdk: type[_Sdk], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "account", None)

    with pytest.raises(PermissionDeniedError) as caught:
        _ask(bridge_url, _OPENING)

    assert caught.value.code == "session_not_isolated"
    assert bridge._POOL._sessions == {}


def test_a_call_to_anything_but_zens_tools_is_refused_and_ends_the_session(
    bridge_url: str, sdk: type[_Sdk]
) -> None:
    assert _ask(bridge_url, _OPENING).content == "hi"
    gate = sdk.started[0].hooks["PreToolUse"][0].hooks[0]

    def asked(tool_name: str) -> dict[str, Any]:
        call = {
            "hook_event_name": "PreToolUse",
            "tool_name": tool_name,
            "tool_input": {},
            "tool_use_id": "t",
        }
        return asyncio.run(gate(call, "t", None))

    assert asked("mcp__zen__lookup") == {}
    assert asked(_FOREIGN)["hookSpecificOutput"]["permissionDecision"] == "deny"

    followed = [
        *_OPENING,
        {"role": "assistant", "content": "hi"},
        {"role": "user", "content": "more"},
    ]
    with pytest.raises(PermissionDeniedError) as caught:
        _ask(bridge_url, followed)
    assert caught.value.code == "session_not_isolated"
    assert _FOREIGN in str(caught.value)


@pytest.mark.asyncio
async def test_a_refused_session_is_put_to_zen_once(
    bridge_url: str, sdk: type[_Sdk], monkeypatch: pytest.MonkeyPatch
) -> None:
    async def no_wait(*_args: Any, **_kwargs: Any) -> None:
        return None

    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)
    monkeypatch.setattr(model_retry, "_sleep_for_retry", no_wait)
    monkeypatch.setattr(sdk, "account", _with(tools=[_FOREIGN]))
    client = AsyncOpenAI(api_key="unused", base_url=bridge_url, timeout=30.0)
    agent: Agent[Any] = Agent(
        name="probe",
        model=OpenAIChatCompletionsModel(model="m", openai_client=client),
        model_settings=ModelSettings(retry=DEFAULT_MODEL_RETRY),
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)

    with pytest.raises(PermissionDeniedError):
        await execution._run_cycle(
            agent,
            coordinator,
            "root",
            input_data="hello",
            run_config=RunConfig(tracing_disabled=True),
            context={},
            max_turns=5,
            session=None,
            interactive=False,
            event_sink=None,
            hooks=None,
        )

    assert len(_Counted.posts) == 1
    assert sdk.queries == 1
