from __future__ import annotations

from typing import Any, cast

import httpx
import pytest
from agents import RunConfig, Runner
from openai import (
    APIConnectionError,
    APIError,
    APIStatusError,
    APITimeoutError,
    AuthenticationError,
    BadRequestError,
    InternalServerError,
    PermissionDeniedError,
    RateLimitError,
)

from zen.config import codex
from zen.core import execution
from zen.core.agents import AgentCoordinator


def _request() -> httpx.Request:
    return httpx.Request("POST", "https://api.openai.com/v1/responses")


def _midstream_api_error() -> APIError:
    return APIError("An error occurred while processing the request.", _request(), body=None)


def _status_error(status: int) -> APIStatusError:
    return APIStatusError(
        f"status {status}",
        response=httpx.Response(status_code=status, request=_request()),
        body=None,
    )


def test_midstream_api_error_is_transient() -> None:
    assert execution._is_transient_model_error(_midstream_api_error()) is True


def test_network_errors_are_transient() -> None:
    assert execution._is_transient_model_error(APITimeoutError(_request())) is True
    assert execution._is_transient_model_error(APIConnectionError(request=_request())) is True


def test_server_errors_are_transient() -> None:
    assert (
        execution._is_transient_model_error(
            InternalServerError("boom", response=httpx.Response(500, request=_request()), body=None)
        )
        is True
    )
    for status in (502, 503, 504, 408):
        assert execution._is_transient_model_error(_status_error(status)) is True


def test_rate_limit_is_retried() -> None:
    rate_limited = RateLimitError(
        "slow down", response=httpx.Response(429, request=_request()), body=None
    )
    assert execution._is_transient_model_error(rate_limited) is True


def test_dns_and_connection_errors_are_transient() -> None:
    assert execution._is_transient_model_error(OSError("nodename nor servname provided")) is True
    assert execution._is_transient_model_error(ConnectionError("reset")) is True
    assert execution._is_transient_model_error(TimeoutError("timed out")) is True


def test_content_guardrail_is_not_retried() -> None:
    guardrail = APIError(
        "This content was flagged for possible cybersecurity risk",
        _request(),
        body=None,
    )
    assert codex.is_content_guardrail_error(guardrail) is True
    assert execution._is_transient_model_error(guardrail) is False


def test_client_errors_are_not_transient() -> None:
    bad_request = BadRequestError(
        "bad", response=httpx.Response(400, request=_request()), body=None
    )
    assert execution._is_transient_model_error(bad_request) is False
    assert execution._is_transient_model_error(_status_error(404)) is False
    assert execution._is_transient_model_error(ValueError("nope")) is False


class _FakeStream:
    def __init__(self, exc: BaseException | None = None) -> None:
        self._exc = exc
        self._events: list[Any] = []
        self.run_loop_exception: BaseException | None = None

    async def stream_events(self) -> Any:
        if self._exc is not None:
            raise self._exc
        for event in self._events:
            yield event


def _patch_fast_backoff(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_BASE_DELAY_S", 0.0)
    monkeypatch.setattr(execution, "_TRANSIENT_MODEL_RETRY_MAX_DELAY_S", 0.0)


async def _run_once(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
) -> Any:
    _patch_fast_backoff(monkeypatch)
    calls = {"n": 0}

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[calls["n"]]
        calls["n"] += 1
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)

    result = await execution._run_cycle(
        object(),
        coordinator,
        "root",
        input_data="task",
        run_config=cast("RunConfig", object()),
        context={},
        max_turns=5,
        session=None,
        interactive=False,
        event_sink=None,
        hooks=None,
    )
    return result, calls["n"], coordinator


@pytest.mark.asyncio
async def test_run_cycle_retries_transient_midstream_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [_FakeStream(exc=_midstream_api_error()), _FakeStream()]
    result, attempts, _coordinator = await _run_once(monkeypatch, streams)

    assert result is streams[1]
    assert attempts == 2


@pytest.mark.asyncio
async def test_run_cycle_gives_up_after_max_retries(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    streams = [
        _FakeStream(exc=_midstream_api_error())
        for _ in range(execution._MAX_TRANSIENT_MODEL_RETRIES + 1)
    ]
    with pytest.raises(APIError):
        await _run_once(monkeypatch, streams)


@pytest.mark.asyncio
async def test_run_cycle_does_not_retry_permanent_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bad_request = BadRequestError(
        "bad", response=httpx.Response(400, request=_request()), body=None
    )
    streams = [_FakeStream(exc=bad_request), _FakeStream()]
    with pytest.raises(BadRequestError):
        await _run_once(monkeypatch, streams)


# --- A status-bearing 401 or 403, at this layer only -------------------------
#
# The tests below pin what the transient predicate and the run cycle do with an
# error that carries a 401 or a 403 status. They make no statement about an error
# that reaches this layer with another status, or with none.

_REJECTIONS = [(401, "typed"), (403, "typed"), (401, "bare"), (403, "bare")]


def _rejection(status: int, shape: str) -> APIStatusError:
    """A 401 or 403 as the SDK's typed error, or as a bare status error."""
    if shape == "bare":
        return _status_error(status)
    error_type = AuthenticationError if status == 401 else PermissionDeniedError
    return error_type(
        f"status {status}",
        response=httpx.Response(status_code=status, request=_request()),
        body=None,
    )


class _FakeSession:
    """A session for the path under test, which only reads the stored items."""

    async def get_items(self) -> list[Any]:
        return []


class _SessionStream(_FakeStream):
    """A fake stream whose (empty) history the failure path can read back."""

    def to_input_list(self) -> list[Any]:
        return []


async def _run_cycle_capturing(
    monkeypatch: pytest.MonkeyPatch,
    streams: list[_FakeStream],
    *,
    session: Any = None,
) -> tuple[APIStatusError | None, int, AgentCoordinator]:
    """Run one cycle; return the status error raised, the runs started, the coordinator."""
    _patch_fast_backoff(monkeypatch)
    started: list[_FakeStream] = []

    def _fake_run_streamed(*_args: Any, **_kwargs: Any) -> _FakeStream:
        stream = streams[len(started)]
        started.append(stream)
        return stream

    monkeypatch.setattr(Runner, "run_streamed", _fake_run_streamed)

    coordinator = AgentCoordinator()
    await coordinator.register("root", "zen", parent_id=None)

    raised: APIStatusError | None = None
    try:
        await execution._run_cycle(
            object(),
            coordinator,
            "root",
            input_data="task",
            run_config=cast("RunConfig", object()),
            context={},
            max_turns=5,
            session=session,
            interactive=False,
            event_sink=None,
            hooks=None,
        )
    except APIStatusError as exc:
        raised = exc
    return raised, len(started), coordinator


@pytest.mark.parametrize(("status", "shape"), _REJECTIONS)
def test_transient_predicate_is_false_for_a_status_bearing_401_or_403(
    status: int, shape: str
) -> None:
    assert execution._is_transient_model_error(_rejection(status, shape)) is False


@pytest.mark.parametrize(("status", "shape"), _REJECTIONS)
@pytest.mark.asyncio
async def test_run_cycle_makes_one_attempt_for_a_status_bearing_401_or_403(
    monkeypatch: pytest.MonkeyPatch, status: int, shape: str
) -> None:
    # No session, so only the transient branch could replay the turn. A second
    # run would consume the healthy stream and the cycle would return, not raise.
    rejection = _rejection(status, shape)
    streams = [_FakeStream(exc=rejection), _FakeStream()]

    raised, attempts, coordinator = await _run_cycle_capturing(monkeypatch, streams)

    assert raised is rejection
    assert attempts == 1
    assert coordinator.statuses["root"] == "failed"


@pytest.mark.parametrize(("status", "shape"), _REJECTIONS)
@pytest.mark.asyncio
async def test_run_cycle_with_a_session_runs_no_recovery_for_a_status_bearing_401_or_403(
    monkeypatch: pytest.MonkeyPatch, status: int, shape: str
) -> None:
    # With a session all three replay branches are reachable. Both recoveries are
    # replaced by stand-ins that report success, so a branch that was entered
    # would replay the turn and show up as a second run.
    strips: list[Any] = []
    forced_compactions: list[Any] = []

    async def _strip(session: Any) -> bool:
        strips.append(session)
        return True

    async def _compact(_agent: Any, session: Any, _run_config: Any, *, force: bool) -> bool:
        if force:
            forced_compactions.append(session)
        return force

    monkeypatch.setattr(execution, "strip_all_images_from_session", _strip)
    monkeypatch.setattr(execution, "_compact_session", _compact)
    rejection = _rejection(status, shape)
    streams: list[_FakeStream] = [_SessionStream(exc=rejection), _SessionStream()]

    raised, attempts, coordinator = await _run_cycle_capturing(
        monkeypatch, streams, session=_FakeSession()
    )

    assert raised is rejection
    assert attempts == 1
    assert strips == []
    assert forced_compactions == []
    assert coordinator.statuses["root"] == "failed"
