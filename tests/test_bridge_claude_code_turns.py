"""What the Claude Code bridge does with a turn that outlasts the request for it.

Scope: the bridge's HTTP handler, its session pool and one session, with a
stand-in for the Agent SDK client. The stand-in keeps the properties of the real
client that the bridge depends on: a session says what it holds before it works,
prompts go to one conversation and are worked through in order, and every reader
of the reply shares one stream of messages. How the Claude Code CLI itself
treats a prompt that arrives while a turn is running is not exercised here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import socket
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from http.server import ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, ClassVar, override
from urllib.parse import urlsplit

import claude_agent_sdk
import httpx
import pytest
from agents import Agent, ModelSettings, RunConfig, function_tool
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from agents.run_internal import model_retry
from claude_agent_sdk import AssistantMessage, ResultMessage, SystemMessage, TextBlock
from openai import (
    APIStatusError,
    APITimeoutError,
    AsyncOpenAI,
    InternalServerError,
    OpenAI,
    PermissionDeniedError,
)

from zen.bridge import claude_code as bridge
from zen.config import models
from zen.config.models import DEFAULT_MODEL_RETRY, _TurnGuardModel
from zen.core import execution
from zen.core.agents import AgentCoordinator


if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


_READERS = 16
_FOREIGN = "mcp__rea__binary_session"
_GONE = "client went away while its turn was running"
_OPENING: list[dict[str, Any]] = [{"role": "user", "content": "hello"}]
_TOOLS: Any = [
    {
        "type": "function",
        "function": {
            "name": "lookup",
            "description": "Look something up.",
            "parameters": {"type": "object", "properties": {}},
        },
    }
]
_RUNS: list[int] = []
_BEFORE_ANSWER: list[Callable[[], None]] = []


@function_tool
def lookup() -> str:
    """Look something up."""
    _RUNS.append(1)
    for act in _BEFORE_ANSWER:
        act()
    return f"result {len(_RUNS)}"


def _result() -> ResultMessage:
    return ResultMessage(
        subtype="success",
        duration_ms=1,
        duration_api_ms=0,
        is_error=False,
        num_turns=1,
        session_id="session",
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


def _holding_also(tool_name: str) -> Any:
    """An account of a session that holds one tool besides what the bridge asked for."""

    def told(options: Any) -> dict[str, Any]:
        account = _as_asked(options)
        account["tools"] = [*account["tools"], tool_name]
        return account

    return told


class _Conversation:
    """Stands in for the Agent SDK client: one conversation, worked through in order."""

    live: ClassVar[list[_Conversation]] = []
    turn: ClassVar[Any] = None
    account: ClassVar[Any] = None
    # Seconds before a reader is told what the session holds; None if the stream
    # ends before it is told anything.
    reports_after: ClassVar[float | None] = 0.0
    readers_told_of_the_end: ClassVar[int] = _READERS

    def __init__(self, options: Any = None) -> None:
        self.options = options
        self.tools = options.mcp_servers["zen"]["tools"]
        self.prompts: list[str] = []
        self.answers: list[str] = []
        self.stream: asyncio.Queue[Any] = asyncio.Queue()
        self._inbox: asyncio.Queue[str] = asyncio.Queue()
        self._reported = asyncio.Event()
        self._worker: asyncio.Task[None] | None = None
        type(self).live.append(self)

    async def connect(self) -> None:
        self._worker = asyncio.get_running_loop().create_task(self._work())

    async def _work(self) -> None:
        while True:
            prompt = await self._inbox.get()
            await self._reported.wait()  # a session says what it holds before it works
            text = await type(self).turn(self, prompt)
            self.stream.put_nowait(AssistantMessage(content=[TextBlock(text=text)], model="m"))
            self.stream.put_nowait(_result())

    async def query(self, prompt: Any) -> None:
        self.prompts.append(str(prompt))
        self._inbox.put_nowait(str(prompt))

    async def call(self, name: str) -> str:
        """The model calls one of zen's tools and reads what it is answered with."""
        reply = await self.tools[name].handler({})
        answer = "".join(block.get("text", "") for block in reply["content"])
        self.answers.append(answer)
        return answer

    async def receive_response(self) -> Any:
        delay = type(self).reports_after
        if delay is None:
            return
        await asyncio.sleep(delay)
        # Each reader is told for itself: a report in the shared stream would be
        # another reader's first message.
        yield SystemMessage(subtype="init", data=type(self).account(self.options))
        self._reported.set()
        while True:
            message = await self.stream.get()
            if message is None:
                return
            yield message
            if isinstance(message, ResultMessage):
                return

    async def disconnect(self) -> None:
        if self._worker is not None:
            self._worker.cancel()
        for _ in range(type(self).readers_told_of_the_end):
            self.stream.put_nowait(None)


def _reply_after(seconds: float) -> Any:
    async def turn(_conversation: _Conversation, prompt: str) -> str:
        await asyncio.sleep(seconds)
        return f"reply to: {prompt}"

    return turn


def _lookups(pauses: tuple[float, ...]) -> Any:
    """A turn that calls the tool once per pause, working that long before each call."""

    async def turn(conversation: _Conversation, _prompt: str) -> str:
        for pause in pauses:
            await asyncio.sleep(pause)
            await conversation.call("lookup")
        return "done"

    return turn


async def _never(_conversation: _Conversation, _prompt: str) -> str:
    await asyncio.Event().wait()
    return ""


async def _cli_goes_away(conversation: _Conversation, _prompt: str) -> str:
    conversation.stream.put_nowait(None)
    await asyncio.Event().wait()
    return ""


def _capture_tools(name: str, version: str = "1.0.0", tools: Any = None) -> dict[str, Any]:
    del version
    return {"type": "sdk", "name": name, "tools": {tool.name: tool for tool in tools or []}}


class _Counted(bridge._Handler):
    posts: ClassVar[list[float]] = []

    @override
    def do_POST(self) -> None:
        type(self).posts.append(time.monotonic())
        super().do_POST()


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> type[_Conversation]:
    monkeypatch.setattr(_Conversation, "live", [])
    monkeypatch.setattr(_Conversation, "turn", _reply_after(0.0))
    monkeypatch.setattr(_Conversation, "account", _as_asked)
    monkeypatch.setattr(_Conversation, "reports_after", 0.0)
    monkeypatch.setattr(_Conversation, "readers_told_of_the_end", _READERS)
    monkeypatch.setattr(_Counted, "posts", [])
    monkeypatch.setattr(claude_agent_sdk, "ClaudeSDKClient", _Conversation)
    monkeypatch.setattr(claude_agent_sdk, "create_sdk_mcp_server", _capture_tools)
    _RUNS.clear()
    _BEFORE_ANSWER.clear()
    return _Conversation


@pytest.fixture
def bridge_url(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    sessions: list[Any] = []
    create = bridge._SessionPool.get_or_create

    def recording(pool: Any, key: str, payload: dict[str, Any]) -> Any:
        made = create(pool, key, payload)
        sessions.append(made[0])
        return made

    monkeypatch.setattr(bridge._SessionPool, "get_or_create", recording)
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Counted)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        bridge._POOL.close_all()
        # A tool call still parked would keep its worker thread, and with it the
        # interpreter, alive: answer every one before leaving.
        for session in sessions:
            for _ in range(_READERS):
                session._tool_results.put([])
        server.shutdown()
        server.server_close()


@pytest.fixture
def _instant_retries(monkeypatch: pytest.MonkeyPatch) -> None:
    async def no_wait(*_args: Any, **_kwargs: Any) -> None:
        """Skip the pause before a retry."""

    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)
    monkeypatch.setattr(model_retry, "_sleep_for_retry", no_wait)


def _ask(base_url: str, messages: Any, *, timeout: float = 30.0) -> Any:
    with OpenAI(api_key="unused", base_url=base_url, max_retries=0, timeout=timeout) as client:
        reply = client.chat.completions.create(model="m", messages=messages, tools=_TOOLS)
    return reply.choices[0].message


def _text(base_url: str, messages: Any, *, timeout: float, stream: bool) -> str:
    """The text a request is answered with, read whole or as a stream."""
    with OpenAI(api_key="unused", base_url=base_url, max_retries=0, timeout=timeout) as client:
        if stream:
            chunks = client.chat.completions.create(model="m", messages=messages, stream=True)
            return "".join(chunk.choices[0].delta.content or "" for chunk in chunks)
        reply = client.chat.completions.create(model="m", messages=messages)
        return reply.choices[0].message.content or ""


def _outcome(base_url: str, messages: list[dict[str, Any]]) -> tuple[Any, float]:
    """What a request came back with, a reply or the error raised, and how long it took."""
    started = time.monotonic()
    try:
        result: Any = _ask(base_url, messages)
    except APIStatusError as exc:
        result = exc
    return result, time.monotonic() - started


def _answered(messages: list[dict[str, Any]], reply: Any, result: str) -> list[dict[str, Any]]:
    """The transcript once ``reply``'s tool call has been run and answered with ``result``."""
    call = reply.tool_calls[0]
    return [
        *messages,
        {
            "role": "assistant",
            "content": None,
            "tool_calls": [
                {
                    "id": call.id,
                    "type": "function",
                    "function": {"name": call.function.name, "arguments": call.function.arguments},
                }
            ],
        },
        {"role": "tool", "tool_call_id": call.id, "content": result},
    ]


def _post_and_leave(base_url: str, body: dict[str, Any], after: float) -> None:
    target = urlsplit(base_url)
    address = (target.hostname or "127.0.0.1", target.port or 80)
    raw = json.dumps(body).encode()
    head = (
        f"POST {target.path}/chat/completions HTTP/1.1\r\nHost: bridge\r\n"
        f"Content-Type: application/json\r\nContent-Length: {len(raw)}\r\n\r\n"
    ).encode()
    with socket.create_connection(address) as connection:
        connection.sendall(head + raw)
        time.sleep(after)


async def _one_cycle(base_url: str, *, idle: float, request_timeout: float = 30.0) -> Any:
    """One run cycle with the real runner, client, retry policy and stream watchdog."""
    client = AsyncOpenAI(
        api_key="unused", base_url=base_url, max_retries=0, timeout=request_timeout
    )
    guarded = _TurnGuardModel(
        OpenAIChatCompletionsModel(model="m", openai_client=client), stream_idle_timeout=idle
    )
    agent: Agent[Any] = Agent(
        name="probe",
        model=guarded,
        model_settings=ModelSettings(retry=DEFAULT_MODEL_RETRY),
        tools=[lookup],
    )
    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)
    return await execution._run_cycle(
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


def test_a_request_repeated_while_its_turn_runs_joins_the_turn(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _reply_after(0.8))

    with pytest.raises(APITimeoutError):
        _ask(bridge_url, _OPENING, timeout=0.3)
    reply = _ask(bridge_url, _OPENING)

    assert reply.content == "reply to: hello"
    assert [conversation.prompts for conversation in sdk.live] == [["hello"]]


def test_a_reply_its_client_did_not_wait_for_is_kept_for_the_request_that_repeats_it(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _reply_after(0.6))

    with pytest.raises(APITimeoutError):
        _ask(bridge_url, _OPENING, timeout=0.2)
    time.sleep(0.8)  # the turn ends while only the request that gave up is waiting
    started = time.monotonic()
    reply = _ask(bridge_url, _OPENING)

    assert reply.content == "reply to: hello"
    assert time.monotonic() - started < 0.5
    assert [conversation.prompts for conversation in sdk.live] == [["hello"]]


def test_tool_results_sent_twice_reach_the_model_once(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _lookups((0.0, 0.8)))

    first = _ask(bridge_url, _OPENING)
    answered = _answered(_OPENING, first, "result 1")
    with pytest.raises(APITimeoutError):
        _ask(bridge_url, answered, timeout=0.3)
    second = _ask(bridge_url, answered)
    final = _ask(bridge_url, _answered(answered, second, "result 2"))

    assert final.content == "done"
    assert len(sdk.live) == 1
    assert sdk.live[0].answers == ["result 1", "result 2"]


def test_a_request_that_opens_a_conversation_is_not_queued_behind_an_earlier_one(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_TURN_TIMEOUT_S", 3.0)
    monkeypatch.setattr(sdk, "turn", _lookups((0.0, 0.0, 0.0)))

    first = _ask(bridge_url, _OPENING)
    _ask(bridge_url, _answered(_OPENING, first, "result 1"))  # the earlier run stops here
    started = time.monotonic()
    again = _ask(bridge_url, _OPENING, timeout=10.0)

    assert again.tool_calls
    assert time.monotonic() - started < 2.0
    assert [conversation.prompts for conversation in sdk.live] == [["hello"], ["hello"]]


def test_a_request_that_opens_a_conversation_does_not_continue_one_that_ended_on_a_reply(
    bridge_url: str, sdk: type[_Conversation]
) -> None:
    first = _ask(bridge_url, _OPENING)
    followed = [
        *_OPENING,
        {"role": "assistant", "content": first.content},
        {"role": "user", "content": "more"},
    ]
    _ask(bridge_url, followed)  # the earlier run ends here, on a reply
    again = _ask(bridge_url, _OPENING)

    assert again.content == "reply to: hello"
    assert [conversation.prompts for conversation in sdk.live] == [["hello", "more"], ["hello"]]


def test_a_user_turn_is_not_queued_behind_a_call_the_session_is_parked_on(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_TURN_TIMEOUT_S", 3.0)
    monkeypatch.setattr(sdk, "turn", _lookups((0.0, 0.0)))

    _ask(bridge_url, _OPENING)  # answered with a tool call; the session is parked on it
    diverged = [
        *_OPENING,
        {"role": "assistant", "content": "noted"},
        {"role": "user", "content": "next"},
    ]
    started = time.monotonic()
    reply = _ask(bridge_url, diverged, timeout=10.0)

    assert reply.tool_calls
    assert time.monotonic() - started < 2.0
    assert [conversation.prompts for conversation in sdk.live] == [["hello"], ["next"]]


def test_a_turn_that_never_ends_is_ended_at_one_deadline_for_every_request_that_joined(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_TURN_TIMEOUT_S", 1.2)
    monkeypatch.setattr(sdk, "turn", _never)

    with ThreadPoolExecutor(max_workers=2) as pool:
        early = pool.submit(_outcome, bridge_url, _OPENING)
        time.sleep(0.6)
        late = pool.submit(_outcome, bridge_url, _OPENING)
        (early_error, early_took), (late_error, late_took) = early.result(), late.result()

    assert isinstance(early_error, InternalServerError)
    assert isinstance(late_error, InternalServerError)
    assert "model turn exceeded" in str(early_error)
    assert "model turn exceeded" in str(late_error)
    assert early_took < 1.6
    assert late_took < 1.0
    assert bridge._POOL._sessions == {}


def test_a_session_closed_under_a_running_turn_answers_with_an_error(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_TURN_TIMEOUT_S", 2.0)
    monkeypatch.setattr(sdk, "readers_told_of_the_end", 0)
    monkeypatch.setattr(sdk, "turn", _never)

    with ThreadPoolExecutor(max_workers=1) as pool:
        waiting = pool.submit(_outcome, bridge_url, _OPENING)
        time.sleep(0.4)
        bridge._POOL.close_all()
        error, _took = waiting.result()

    assert isinstance(error, InternalServerError)
    assert error.code == "turn_incomplete"


def _parked_workers(before: set[threading.Thread]) -> list[threading.Thread]:
    """Worker threads started since ``before`` by a session's loop to wait on a parked call."""
    return [
        thread
        for thread in threading.enumerate()
        if thread not in before and thread.name.startswith("asyncio")
    ]


def test_a_session_closed_while_parked_on_a_call_leaves_no_thread_waiting(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _lookups((0.0,)))
    before = set(threading.enumerate())

    assert _ask(bridge_url, _OPENING).tool_calls  # the session is parked on this call
    give_up = time.monotonic() + 1.0
    while not _parked_workers(before) and time.monotonic() < give_up:
        time.sleep(0.01)
    parked = _parked_workers(before)
    bridge._POOL.close_all()
    for thread in parked:
        thread.join(timeout=2.0)

    assert len(parked) == 1
    assert not any(thread.is_alive() for thread in parked)


def test_a_stream_that_ends_before_the_turn_does_is_an_error_not_an_empty_reply(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _cli_goes_away)

    with pytest.raises(InternalServerError) as caught:
        _ask(bridge_url, _OPENING)

    assert caught.value.status_code == 502
    assert caught.value.code == "turn_incomplete"
    assert bridge._POOL._sessions == {}


def test_a_stream_that_ends_before_the_session_reports_is_an_error_not_a_refusal(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "reports_after", None)

    with pytest.raises(InternalServerError) as caught:
        _ask(bridge_url, _OPENING)

    assert caught.value.status_code == 502
    assert caught.value.code == "turn_incomplete"


def test_a_refused_session_is_answered_as_refused_to_every_request_that_joined(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "account", _holding_also(_FOREIGN))
    monkeypatch.setattr(sdk, "reports_after", 0.6)

    with ThreadPoolExecutor(max_workers=2) as pool:
        early = pool.submit(_outcome, bridge_url, _OPENING)
        time.sleep(0.3)
        late = pool.submit(_outcome, bridge_url, _OPENING)
        refusals = [early.result()[0], late.result()[0]]

    for refusal in refusals:
        assert isinstance(refusal, PermissionDeniedError)
        assert refusal.type == "bridge_error"
        assert refusal.code == "session_not_isolated"
        assert _FOREIGN in str(refusal)
    assert len(sdk.live) == 1
    assert bridge._POOL._sessions == {}


def test_a_kept_reply_is_refused_once_the_session_has_been_asked_for_another_tool(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _reply_after(0.5))

    with pytest.raises(APITimeoutError):
        _ask(bridge_url, _OPENING, timeout=0.2)
    time.sleep(0.7)  # the reply is kept while only the request that gave up is waiting
    gate = sdk.live[0].options.hooks["PreToolUse"][0].hooks[0]
    asked = {
        "hook_event_name": "PreToolUse",
        "tool_name": _FOREIGN,
        "tool_input": {},
        "tool_use_id": "t",
    }
    asyncio.run(gate(asked, "t", None))

    with pytest.raises(PermissionDeniedError) as caught:
        _ask(bridge_url, _OPENING)

    assert caught.value.code == "session_not_isolated"
    assert _FOREIGN in str(caught.value)
    assert [conversation.prompts for conversation in sdk.live] == [["hello"]]
    assert bridge._POOL._sessions == {}


@pytest.mark.parametrize("stream", [False, True])
def test_a_client_waiting_on_a_running_turn_is_sent_interim_responses(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch, stream: bool
) -> None:
    monkeypatch.setattr(bridge, "_PROGRESS_INTERVAL_S", 0.2)
    monkeypatch.setattr(sdk, "turn", _reply_after(1.0))

    assert _text(bridge_url, _OPENING, timeout=0.5, stream=stream) == "reply to: hello"
    assert len(_Counted.posts) == 1


def test_a_client_that_goes_away_ends_its_wait_and_leaves_the_turn_running(
    bridge_url: str,
    sdk: type[_Conversation],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(bridge, "_PROGRESS_INTERVAL_S", 0.1)
    monkeypatch.setattr(sdk, "turn", _reply_after(1.5))
    caplog.set_level(logging.INFO, logger="zen.bridge.claude_code")

    _post_and_leave(bridge_url, {"model": "m", "messages": _OPENING, "tools": _TOOLS}, after=0.25)
    give_up = time.monotonic() + 1.0
    while _GONE not in caplog.text and time.monotonic() < give_up:
        time.sleep(0.05)

    assert _GONE in caplog.text
    assert len(bridge._POOL._sessions) == 1
    assert _ask(bridge_url, _OPENING).content == "reply to: hello"
    assert [conversation.prompts for conversation in sdk.live] == [["hello"]]


def test_the_health_reply_declares_the_turn_bound_zen_reads(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(bridge, "_TURN_TIMEOUT_S", 42.0)
    monkeypatch.setattr(models, "_BRIDGE_TURN_BOUNDS", {})

    health = httpx.get(f"{bridge_url.removesuffix('/v1')}/health", timeout=5.0)

    assert health.status_code == 200
    assert health.json() == {"status": "ok", "turn_timeout_s": 42.0}
    assert models._bridge_turn_bound(bridge_url) == 42.0


@pytest.mark.asyncio
@pytest.mark.usefixtures("_instant_retries")
async def test_a_turn_longer_than_the_idle_limit_is_answered_and_the_model_is_prompted_once(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _lookups((0.9,)))

    stream = await _one_cycle(bridge_url, idle=0.4)

    assert stream.final_output == "done"
    assert [conversation.prompts for conversation in sdk.live] == [["hello"]]
    assert sdk.live[0].answers == ["result 1"]
    assert _RUNS == [1]


@pytest.mark.asyncio
@pytest.mark.usefixtures("_instant_retries")
async def test_a_working_turn_is_not_given_up_on_when_a_local_bridge_declares_its_turn_bound(
    bridge_url: str,
    sdk: type[_Conversation],
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(models, "_BRIDGE_TURN_BOUNDS", {})
    monkeypatch.setattr(bridge, "_PROGRESS_INTERVAL_S", 0.2)
    monkeypatch.setattr(sdk, "turn", _lookups((1.5,)))

    idle = models._idle_limit_for_endpoint(0.4, bridge_url)
    stream = await _one_cycle(bridge_url, idle=idle, request_timeout=0.6)

    assert stream.final_output == "done"
    assert len(_Counted.posts) == 2
    assert "abandoning the turn" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.usefixtures("_instant_retries")
async def test_tool_results_for_a_conversation_the_bridge_no_longer_holds_are_refused_once(
    bridge_url: str, sdk: type[_Conversation], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(sdk, "turn", _lookups((0.0,)))
    _BEFORE_ANSWER.append(bridge._POOL.close_all)

    with pytest.raises(APIStatusError) as caught:
        await _one_cycle(bridge_url, idle=30.0)

    assert caught.value.status_code == 410
    assert caught.value.code == "conversation_not_held"
    assert len(_Counted.posts) == 2
    assert len(sdk.live) == 1
