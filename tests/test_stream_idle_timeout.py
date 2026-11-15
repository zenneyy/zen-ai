"""Tests for the model-stream idle watchdog.

A turn that streams a few tokens and then goes silent is not covered by the
request timeout: the read timeout resets on every byte, keepalives included.
The watchdog bounds the gap between events so the turn fails and can be
retried instead of parking the agent forever.
"""

from __future__ import annotations

import asyncio
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import TYPE_CHECKING, Any, ClassVar, override

import pytest
from agents.model_settings import ModelSettings
from agents.models.interface import Model, ModelTracing
from agents.models.openai_chatcompletions import OpenAIChatCompletionsModel
from openai import AsyncOpenAI

from zen.config import loader, models
from zen.config.loader import load_settings
from zen.config.models import ZenProvider, _TurnGuardModel, _with_idle_timeout


if TYPE_CHECKING:
    from collections.abc import AsyncIterator, Iterator


_STALL_SECONDS = 30.0


def _chunk(text: str) -> bytes:
    payload = {
        "id": "chatcmpl-1",
        "object": "chat.completion.chunk",
        "created": 0,
        "model": "gw-model",
        "choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}],
    }
    return b"data: " + json.dumps(payload).encode() + b"\n\n"


class _StallingHandler(BaseHTTPRequestHandler):
    """Streams a couple of tokens, then stops producing anything."""

    stop = threading.Event()

    def log_message(self, *args: Any) -> None:
        pass

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        self.wfile.write(_chunk("Now"))
        self.wfile.write(_chunk(" spawning"))
        self.wfile.flush()
        self.stop.wait(_STALL_SECONDS)


@pytest.fixture
def stalling_gateway() -> Iterator[str]:
    _StallingHandler.stop.clear()
    server = HTTPServer(("127.0.0.1", 0), _StallingHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        _StallingHandler.stop.set()
        server.shutdown()
        server.server_close()


def _stream(base_url: str, *, idle_timeout: float) -> AsyncIterator[Any]:
    client = AsyncOpenAI(api_key="tok", base_url=base_url, max_retries=0, timeout=_STALL_SECONDS)
    inner: Model = OpenAIChatCompletionsModel(model="gw-model", openai_client=client)
    guarded = _TurnGuardModel(inner, stream_idle_timeout=idle_timeout)
    return guarded.stream_response(
        None,
        "go",
        ModelSettings(),
        [],
        None,
        [],
        ModelTracing.DISABLED,
        previous_response_id=None,
        conversation_id=None,
        prompt=None,
    )


async def _drain(base_url: str, *, idle_timeout: float) -> list[Any]:
    return [event async for event in _stream(base_url, idle_timeout=idle_timeout)]


@pytest.mark.asyncio
async def test_stalled_stream_hangs_without_the_watchdog(stalling_gateway: str) -> None:
    # Repro: tokens arrive, then nothing. Un-watched, the turn just sits there;
    # the request timeout is far away and would reset on any keepalive byte.
    with pytest.raises(TimeoutError):
        await asyncio.wait_for(_drain(stalling_gateway, idle_timeout=0), timeout=2)


@pytest.mark.asyncio
async def test_stalled_stream_is_abandoned_by_the_watchdog(stalling_gateway: str) -> None:
    started = time.monotonic()
    with pytest.raises(TimeoutError, match="produced no event"):
        await _drain(stalling_gateway, idle_timeout=1)

    assert time.monotonic() - started < _STALL_SECONDS


@pytest.mark.asyncio
async def test_events_keep_flowing_while_the_stream_is_alive() -> None:
    async def _live() -> AsyncIterator[Any]:
        for i in range(5):
            await asyncio.sleep(0.05)
            yield f"event-{i}"

    seen: list[Any] = [event async for event in _with_idle_timeout(_live(), 1.0)]

    assert seen == [f"event-{i}" for i in range(5)]


@pytest.fixture
def _reset_settings(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    for key in ("ZEN_LLM", "LLM_DISABLE_STREAMING", "LLM_STREAM_IDLE_TIMEOUT"):
        monkeypatch.delenv(key, raising=False)
    # No endpoint on this machine is asked: the limit under test is the configured one.
    monkeypatch.setattr(models, "_bridge_turn_bound", lambda _base_url: None)
    monkeypatch.setattr(loader, "_cached", None)
    monkeypatch.setattr(loader, "_override", None)
    yield


class _DummyModel(Model):
    async def get_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError

    def stream_response(self, *args: Any, **kwargs: Any) -> Any:
        raise NotImplementedError


def test_idle_timeout_is_configurable(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    monkeypatch.setattr("zen.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    load_settings()

    model = ZenProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_idle_timeout == 45


def test_idle_timeout_is_off_without_streaming(
    monkeypatch: pytest.MonkeyPatch, _reset_settings: None
) -> None:
    # LLM_DISABLE_STREAMING turns the whole request into one event, so an idle
    # gap would just be the request duration — the request timeout bounds that.
    monkeypatch.setattr("zen.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    monkeypatch.setenv("LLM_DISABLE_STREAMING", "true")
    load_settings()

    model = ZenProvider().get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_idle_timeout == 0


class _HealthHandler(BaseHTTPRequestHandler):
    """Answers a health check with whatever the test set."""

    status: ClassVar[int] = 200
    body: ClassVar[bytes] = b"{}"

    @override
    def log_message(self, *args: Any) -> None:
        """Keep the test output quiet."""

    def do_GET(self) -> None:
        self.send_response(type(self).status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(type(self).body)))
        self.end_headers()
        self.wfile.write(type(self).body)


@pytest.fixture
def local_endpoint(monkeypatch: pytest.MonkeyPatch) -> Iterator[str]:
    monkeypatch.setattr(models, "_BRIDGE_TURN_BOUNDS", {})
    server = HTTPServer(("127.0.0.1", 0), _HealthHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/v1"
    finally:
        server.shutdown()
        server.server_close()


def _declares(monkeypatch: pytest.MonkeyPatch, health: Any, *, status: int = 200) -> None:
    monkeypatch.setattr(_HealthHandler, "status", status)
    monkeypatch.setattr(_HealthHandler, "body", json.dumps(health).encode())


def test_a_local_bridge_is_known_by_the_turn_bound_its_health_reply_declares(
    local_endpoint: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    _declares(monkeypatch, {"status": "ok", "turn_timeout_s": 1800.0})

    assert models._idle_limit_for_endpoint(45.0, local_endpoint) == 1860.0


@pytest.mark.parametrize(
    ("health", "status"),
    [
        ({"status": "ok"}, 200),
        ({"status": "ok", "turn_timeout_s": "soon"}, 200),
        ({"status": "ok", "turn_timeout_s": True}, 200),
        ({"status": "ok", "turn_timeout_s": 0}, 200),
        ({"status": "ok", "turn_timeout_s": float("inf")}, 200),
        ({"status": "ok", "turn_timeout_s": 10**400}, 200),
        ({"error": "not found"}, 404),
    ],
)
def test_a_local_endpoint_that_declares_no_usable_turn_bound_keeps_its_idle_limit(
    local_endpoint: str, monkeypatch: pytest.MonkeyPatch, health: Any, status: int
) -> None:
    _declares(monkeypatch, health, status=status)

    assert models._idle_limit_for_endpoint(45.0, local_endpoint) == 45.0


def test_an_endpoint_on_another_machine_is_not_asked_and_keeps_its_idle_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def asked(address: str) -> float | None:
        raise AssertionError(f"asked {address}")

    monkeypatch.setattr(models, "_BRIDGE_TURN_BOUNDS", {})
    monkeypatch.setattr(models, "_ask_bridge", asked)

    assert models._idle_limit_for_endpoint(45.0, "https://models.example.com/v1") == 45.0


@pytest.mark.parametrize("base_url", ["http://localhost:not-a-port/v1", "http://[::1/v1"])
def test_a_local_address_that_cannot_be_asked_keeps_its_idle_limit(
    monkeypatch: pytest.MonkeyPatch, base_url: str
) -> None:
    monkeypatch.setattr(models, "_BRIDGE_TURN_BOUNDS", {})

    assert models._idle_limit_for_endpoint(45.0, base_url) == 45.0


@pytest.mark.parametrize(
    ("limit", "bound", "expected"), [(300.0, 120.0, 300.0), (0.0, 1800.0, 0.0)]
)
def test_a_bridges_turn_bound_never_shortens_the_idle_limit_or_arms_it(
    monkeypatch: pytest.MonkeyPatch, limit: float, bound: float, expected: float
) -> None:
    monkeypatch.setattr(models, "_bridge_turn_bound", lambda _base_url: bound)

    assert models._idle_limit_for_endpoint(limit, "http://127.0.0.1:8787/v1") == expected


@pytest.mark.usefixtures("_reset_settings")
def test_the_idle_limit_of_a_model_served_by_a_local_bridge_waits_out_its_turn_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bridge = "http://127.0.0.1:8787/v1"
    monkeypatch.setattr("zen.config.models.MultiProvider.get_model", lambda *_: _DummyModel())
    monkeypatch.setattr(
        models, "_bridge_turn_bound", lambda base_url: 1800.0 if base_url == bridge else None
    )
    monkeypatch.setenv("LLM_STREAM_IDLE_TIMEOUT", "45")
    load_settings()

    model = ZenProvider(base_url=bridge).get_model("openai/gpt-4o-mini")
    assert isinstance(model, _TurnGuardModel)
    assert model._stream_idle_timeout == 1860
