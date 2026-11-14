"""What the top-tools bridge tells its client when a request fails.

Scope: the bridge's HTTP handler, served on a loopback socket and read through
a real OpenAI client. The upstream is a stand-in for the pooled session, so each
test states the upstream's answer and reads what the client receives. What the
layers above the client do with each typed error is pinned where those layers
live, and is not asserted here.
"""

from __future__ import annotations

import json
import logging
import threading
from http.server import ThreadingHTTPServer
from typing import TYPE_CHECKING, Any, Self

import pytest
import requests
from openai import (
    APIError,
    APIStatusError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    NotFoundError,
    OpenAI,
    PermissionDeniedError,
    RateLimitError,
    UnprocessableEntityError,
)

from zen.bridge import top_tools_ai as bridge


if TYPE_CHECKING:
    from collections.abc import Iterator


_UPSTREAM_KEY = "upstream-key-placeholder"
_INBOUND_KEY = "inbound-key-placeholder"
_OTHER_CREDENTIAL = "abcdefgh12345678"
_MESSAGES = [{"role": "user", "content": "hello"}]
_EARLY_SECONDS = 5.0
_STALL_SECONDS = 30.0


def _error_body(message: str, code: str) -> str:
    error = {"message": message, "type": "invalid_request_error", "code": code, "param": None}
    return json.dumps({"error": error})


def _completion(text: str) -> str:
    message = {"role": "assistant", "content": text}
    return json.dumps(
        {
            "id": "chatcmpl-1",
            "object": "chat.completion",
            "created": 0,
            "model": "m",
            "choices": [{"index": 0, "message": message, "finish_reason": "stop"}],
        }
    )


def _chunk(text: str) -> dict[str, Any]:
    return {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "m",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }


class _Answer:
    """One upstream response: a status and a body."""

    def __init__(self, status_code: int, text: str = "") -> None:
        self.status_code = status_code
        self.text = text

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    def close(self) -> None:
        """Nothing to release."""


class _Upstream:
    """Stands in for the pooled upstream session; the last answer repeats."""

    def __init__(self, *answers: _Answer | Exception) -> None:
        self._answers = answers
        self.posts: list[dict[str, Any]] = []

    def post(self, _url: str, **kwargs: Any) -> _Answer:
        self.posts.append(kwargs)
        answer = self._answers[min(len(self.posts), len(self._answers)) - 1]
        if isinstance(answer, Exception):
            raise answer
        return answer


@pytest.fixture
def bridge_url(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setenv("TOP_TOOLS_AI_API_KEY", _UPSTREAM_KEY)
    monkeypatch.setenv("TOP_TOOLS_AI_BASE_URL", "https://upstream.example/v1")
    monkeypatch.setattr(bridge, "_MAX_ATTEMPTS", 3)
    monkeypatch.setattr(bridge, "_retry_delay", lambda _attempt: 0.0)
    server = ThreadingHTTPServer(("127.0.0.1", 0), bridge._Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _upstream(monkeypatch: pytest.MonkeyPatch, *answers: _Answer | Exception) -> _Upstream:
    upstream = _Upstream(*answers)
    monkeypatch.setattr(bridge, "_session", lambda: upstream)
    return upstream


def _client(base_url: str) -> OpenAI:
    return OpenAI(api_key=_INBOUND_KEY, base_url=base_url, max_retries=0, timeout=_STALL_SECONDS)


def _complete(base_url: str, *, stream: bool) -> list[str]:
    """One completion through a real client: the text of every piece received."""
    with _client(base_url) as client:
        if not stream:
            reply = client.chat.completions.create(model="m", messages=_MESSAGES)
            return [reply.choices[0].message.content or ""]
        chunks = client.chat.completions.create(model="m", messages=_MESSAGES, stream=True)
        return [chunk.choices[0].delta.content or "" for chunk in chunks]


_REJECTIONS = [
    (400, BadRequestError),
    (401, AuthenticationError),
    (403, PermissionDeniedError),
    (404, NotFoundError),
    (422, UnprocessableEntityError),
]
_GIVEN_UP = [(429, RateLimitError), (503, InternalServerError)]
_STATUSLESS = [
    (requests.ConnectionError("connection refused"), "upstream_unreachable", 3),
    (_Answer(200, "<html>not a completion</html>"), "upstream_invalid_response", 1),
    (_Answer(302, "moved"), "upstream_unexpected_status", 1),
]


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize(("status", "error_type"), _REJECTIONS)
def test_an_upstream_error_status_reaches_the_client_as_the_same_typed_error(
    bridge_url: str,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    error_type: type[APIStatusError],
    stream: bool,
) -> None:
    refusal = _Answer(status, _error_body("refused upstream", "refusal_code"))
    upstream = _upstream(monkeypatch, refusal)

    with pytest.raises(APIStatusError) as caught:
        _complete(bridge_url, stream=stream)

    assert type(caught.value) is error_type
    assert caught.value.status_code == status
    assert caught.value.code == "refusal_code"
    assert caught.value.type == "invalid_request_error"
    assert "refused upstream" in str(caught.value)
    assert len(upstream.posts) == 1


def test_the_error_body_is_an_openai_error_object(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    upstream = _upstream(
        monkeypatch,
        _Answer(200, _completion("fine")),
        _Answer(401, _error_body("Incorrect API key provided", "invalid_api_key")),
    )
    request = {"model": "m", "messages": _MESSAGES}

    served = requests.post(f"{bridge_url}/chat/completions", json=request, timeout=_STALL_SECONDS)
    refused = requests.post(f"{bridge_url}/chat/completions", json=request, timeout=_STALL_SECONDS)

    assert served.status_code == 200
    assert served.json()["choices"][0]["message"]["content"] == "fine"
    assert refused.status_code == 401
    assert refused.json() == {
        "error": {
            "message": "upstream returned 401: Incorrect API key provided",
            "type": "invalid_request_error",
            "code": "invalid_api_key",
            "param": None,
        }
    }
    assert len(upstream.posts) == 2


def test_an_upstream_error_that_is_not_json_keeps_its_status_and_its_text(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _upstream(monkeypatch, _Answer(403, "Forbidden by upstream policy"))

    with pytest.raises(PermissionDeniedError) as caught:
        _complete(bridge_url, stream=False)

    assert caught.value.type == "upstream_error"
    assert caught.value.code is None
    assert "Forbidden by upstream policy" in str(caught.value)


@pytest.mark.parametrize("stream", [False, True])
@pytest.mark.parametrize(("status", "error_type"), _GIVEN_UP)
def test_a_status_the_bridge_gave_up_retrying_is_passed_on(
    bridge_url: str,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
    error_type: type[APIStatusError],
    stream: bool,
) -> None:
    upstream = _upstream(monkeypatch, _Answer(status))

    with pytest.raises(APIStatusError) as caught:
        _complete(bridge_url, stream=stream)

    assert type(caught.value) is error_type
    assert caught.value.status_code == status
    assert caught.value.type == "upstream_error"
    assert len(upstream.posts) == 3


@pytest.mark.parametrize(("answer", "code", "posts"), _STATUSLESS)
def test_a_failure_with_no_upstream_error_status_is_a_bad_gateway(
    bridge_url: str,
    monkeypatch: pytest.MonkeyPatch,
    answer: _Answer | Exception,
    code: str,
    posts: int,
) -> None:
    upstream = _upstream(monkeypatch, answer)

    with pytest.raises(InternalServerError) as caught:
        _complete(bridge_url, stream=False)

    assert caught.value.status_code == 502
    assert caught.value.type == "bridge_error"
    assert caught.value.code == code
    assert len(upstream.posts) == posts


@pytest.mark.parametrize("stream", [False, True])
def test_a_missing_upstream_key_is_an_authentication_error_and_sends_nothing(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch, stream: bool
) -> None:
    upstream = _upstream(monkeypatch, _Answer(200, _completion("unreachable")))
    monkeypatch.delenv("TOP_TOOLS_AI_API_KEY")
    monkeypatch.setattr(bridge, "_load_key_from_ultron_providers", lambda: "")

    with pytest.raises(AuthenticationError) as caught:
        _complete(bridge_url, stream=stream)

    assert caught.value.status_code == 401
    assert caught.value.type == "bridge_error"
    assert caught.value.code == "upstream_key_missing"
    assert upstream.posts == []


@pytest.mark.parametrize("stream", [False, True])
def test_no_credential_reaches_the_error_body_or_the_log(
    bridge_url: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    stream: bool,
) -> None:
    echo = (
        f"rejected key {_UPSTREAM_KEY}, sent as Bearer {_UPSTREAM_KEY}; "
        f"also saw Bearer {_OTHER_CREDENTIAL}"
    )
    upstream = _upstream(monkeypatch, _Answer(401, _error_body(echo, _UPSTREAM_KEY)))

    with (
        caplog.at_level(logging.DEBUG, logger="zen.bridge"),
        pytest.raises(AuthenticationError) as caught,
    ):
        _complete(bridge_url, stream=stream)

    assert upstream.posts[0]["headers"]["Authorization"] == f"Bearer {_UPSTREAM_KEY}"
    assert "bridge request failed with HTTP 401" in caplog.text
    assert caught.value.code == "[redacted]"
    shown = f"{caught.value} {caught.value.body} {caplog.text}"
    assert "[redacted]" in shown
    for credential in (_UPSTREAM_KEY, _INBOUND_KEY, _OTHER_CREDENTIAL):
        assert credential not in shown


def test_a_stream_frame_reaches_the_client_before_the_upstream_finishes(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()
    first_seen = threading.Event()
    received: list[str] = []

    def _held_open(**_kwargs: Any) -> Iterator[Any]:
        yield "data", _chunk("one"), ""
        yield "data", _chunk("two"), ""
        release.wait(_STALL_SECONDS)
        yield "done", None, "[DONE]"

    def _read() -> None:
        with _client(bridge_url) as client:
            chunks = client.chat.completions.create(model="m", messages=_MESSAGES, stream=True)
            for chunk in chunks:
                received.append(chunk.choices[0].delta.content or "")
                first_seen.set()

    monkeypatch.setattr(bridge, "_stream_upstream", _held_open)
    reader = threading.Thread(target=_read, daemon=True)
    reader.start()
    try:
        arrived_while_open = first_seen.wait(_EARLY_SECONDS)
    finally:
        release.set()
        reader.join(_STALL_SECONDS)

    assert arrived_while_open
    assert received == ["one", "two"]


def test_a_failure_after_the_first_frame_ends_the_stream_with_an_error(
    bridge_url: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    def _cut_short(**_kwargs: Any) -> Iterator[Any]:
        yield "data", _chunk("partial"), ""
        raise requests.exceptions.ChunkedEncodingError(f"connection broken, key {_UPSTREAM_KEY}")

    monkeypatch.setattr(bridge, "_stream_upstream", _cut_short)
    received: list[str] = []

    with _client(bridge_url) as client, pytest.raises(APIError) as caught:
        chunks = client.chat.completions.create(model="m", messages=_MESSAGES, stream=True)
        for chunk in chunks:
            text = chunk.choices[0].delta.content or ""
            received.append(text)

    assert received == ["partial"]
    assert not isinstance(caught.value, APIStatusError)
    assert caught.value.code == "upstream_stream_interrupted"
    assert "ChunkedEncodingError" in str(caught.value)
    assert _UPSTREAM_KEY not in str(caught.value)
