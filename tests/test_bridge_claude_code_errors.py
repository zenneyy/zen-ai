"""What the Claude Code bridge tells its client when the Agent SDK reports a failure.

Scope: the bridge's HTTP handler and its session, with a stand-in for the Agent
SDK client that emits the SDK's own message types. What the Claude Code CLI
really sends for each kind of failure is not exercised here.
"""

from __future__ import annotations

import threading
from http.server import ThreadingHTTPServer
from typing import TYPE_CHECKING, Any

import claude_agent_sdk
import pytest
from claude_agent_sdk import AssistantMessage, ResultMessage, SystemMessage, TextBlock
from openai import (
    APIStatusError,
    AuthenticationError,
    InternalServerError,
    OpenAI,
    PermissionDeniedError,
)

from zen.bridge import claude_code as bridge


if TYPE_CHECKING:
    from collections.abc import Iterator


_CLI_TEXT = "Failed to authenticate. API Error: 401 authentication_error"
_MESSAGES = [{"role": "user", "content": "hello"}]


class _FakeSdkClient:
    """Stands in for the Agent SDK client; replays one scripted turn per query."""

    script: tuple[Any, ...] = ()
    failure: Exception | None = None
    queries = 0

    def __init__(self, options: Any = None) -> None:
        self.options = options

    async def connect(self) -> None:
        """Nothing to start."""

    async def query(self, _prompt: Any) -> None:
        type(self).queries += 1

    async def receive_response(self) -> Any:
        failure = type(self).failure
        if failure is not None:
            raise failure
        yield _session_report(self.options)
        for message in type(self).script:
            yield message

    async def disconnect(self) -> None:
        """Nothing to stop."""


def _session_report(options: Any) -> SystemMessage:
    """The account Claude Code gives of a session that holds what the bridge asked for."""
    return SystemMessage(
        subtype="init",
        data={
            "tools": list(options.allowed_tools),
            "mcp_servers": [{"name": name, "status": "connected"} for name in options.mcp_servers],
            "plugins": [],
            "skills": [],
            "cwd": options.cwd,
            "permissionMode": options.permission_mode,
        },
    )


@pytest.fixture
def sdk(monkeypatch: pytest.MonkeyPatch) -> type[_FakeSdkClient]:
    monkeypatch.setattr(_FakeSdkClient, "script", ())
    monkeypatch.setattr(_FakeSdkClient, "failure", None)
    monkeypatch.setattr(_FakeSdkClient, "queries", 0)
    monkeypatch.setattr(claude_agent_sdk, "ClaudeSDKClient", _FakeSdkClient)
    return _FakeSdkClient


@pytest.fixture
def bridge_url() -> Iterator[str]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge._Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        bridge._POOL.close_all()
        server.shutdown()
        server.server_close()


def _refused(kind: str | None, api_status: int | None) -> tuple[Any, ...]:
    """A turn the SDK reports as failed: a typed message, then an errored result."""
    return (
        AssistantMessage(content=[TextBlock(text=_CLI_TEXT)], model="<synthetic>", error=kind),
        ResultMessage(
            subtype="success",
            duration_ms=1,
            duration_api_ms=0,
            is_error=True,
            num_turns=1,
            session_id="session",
            result=_CLI_TEXT,
            api_error_status=api_status,
        ),
    )


def _complete(base_url: str, *, stream: bool = False) -> str:
    with OpenAI(api_key="unused", base_url=base_url, max_retries=0, timeout=30.0) as client:
        if stream:
            chunks = client.chat.completions.create(model="m", messages=_MESSAGES, stream=True)
            return "".join(chunk.choices[0].delta.content or "" for chunk in chunks)
        reply = client.chat.completions.create(model="m", messages=_MESSAGES)
        return reply.choices[0].message.content or ""


_SIGN_IN_SHAPES = [
    ("authentication_failed", None, AuthenticationError),
    (None, 401, AuthenticationError),
    ("authentication_failed", 403, PermissionDeniedError),
    ("oauth_org_not_allowed", None, PermissionDeniedError),
]


@pytest.mark.parametrize("stream", [False, True])
def test_a_sign_in_failure_the_sdk_reports_is_answered_as_a_401(
    bridge_url: str, sdk: type[_FakeSdkClient], stream: bool
) -> None:
    sdk.script = _refused("authentication_failed", 401)

    with pytest.raises(AuthenticationError) as caught:
        _complete(bridge_url, stream=stream)

    assert caught.value.status_code == 401
    assert caught.value.type == "upstream_error"
    assert caught.value.code == "authentication_failed"
    assert _CLI_TEXT in str(caught.value)
    assert sdk.queries == 1
    assert bridge._POOL._sessions == {}


@pytest.mark.parametrize(("kind", "api_status", "error_type"), _SIGN_IN_SHAPES)
def test_the_status_comes_from_the_failed_call_or_else_from_the_typed_kind(
    bridge_url: str,
    sdk: type[_FakeSdkClient],
    kind: str | None,
    api_status: int | None,
    error_type: type[APIStatusError],
) -> None:
    sdk.script = _refused(kind, api_status)

    with pytest.raises(APIStatusError) as caught:
        _complete(bridge_url)

    assert type(caught.value) is error_type


def test_a_turn_the_sdk_does_not_flag_as_failed_is_passed_on_as_it_is(
    bridge_url: str, sdk: type[_FakeSdkClient]
) -> None:
    message, result = _refused("authentication_failed", None)
    result.is_error = False
    sdk.script = (message, result)

    assert _complete(bridge_url) == _CLI_TEXT


def test_a_session_failure_with_no_upstream_status_is_still_a_bad_gateway(
    bridge_url: str, sdk: type[_FakeSdkClient]
) -> None:
    sdk.failure = RuntimeError("Command failed with exit code 1")

    with pytest.raises(InternalServerError) as caught:
        _complete(bridge_url)

    assert caught.value.status_code == 502
    assert caught.value.type == "bridge_error"
    assert caught.value.code is None
