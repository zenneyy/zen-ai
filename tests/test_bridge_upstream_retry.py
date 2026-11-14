"""The bridge's upstream retry loop, on its own.

Scope: ``_open_upstream`` -- how many times it POSTs upstream for a given
status, and what it hands back. What the bridge's HTTP handler then tells its
client is a different layer and is not asserted here.
"""

from __future__ import annotations

from typing import Any

import pytest

from zen.bridge import top_tools_ai as bridge


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code
        self.closed = False

    def close(self) -> None:
        self.closed = True


class _FakeUpstream:
    """Stands in for the pooled HTTP session; answers every POST with one status."""

    def __init__(self, status_code: int) -> None:
        self._status_code = status_code
        self.responses: list[_FakeResponse] = []

    def post(self, _url: str, **_kwargs: Any) -> _FakeResponse:
        response = _FakeResponse(self._status_code)
        self.responses.append(response)
        return response


@pytest.mark.parametrize("status", [401, 403])
def test_upstream_loop_returns_a_401_or_403_after_one_post(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    upstream = _FakeUpstream(status)
    backoffs: list[int] = []

    def _record_backoff(attempt: int) -> float:
        backoffs.append(attempt)
        return 0.0

    monkeypatch.setattr(bridge, "_session", lambda: upstream)
    monkeypatch.setattr(bridge, "_retry_delay", _record_backoff)
    monkeypatch.setattr(bridge, "_MAX_ATTEMPTS", 3)

    response = bridge._open_upstream(
        url="https://upstream.example/v1/chat/completions",
        api_key="placeholder",
        payload={"messages": []},
        timeout=1.0,
        stream=False,
    )

    assert response is upstream.responses[0]
    assert len(upstream.responses) == 1
    assert response.closed is False
    assert backoffs == []
