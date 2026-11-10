"""A concrete live :class:`~zen.validation.library.Replayer` — transport only.

The :class:`~zen.validation.library.Replayer` the validator library depends on is
a *Protocol*: "re-execute this evidence and tell me what you saw." :mod:`library`
and :mod:`reviewer` are tested against a stub that returns a fixed observation, so
the one thing the Protocol has lacked is a **concrete implementation that actually
re-issues a captured request against the live surface and reads the fresh
response**. This module supplies it for the ``http`` medium.

**This file is TRANSPORT, and only transport.** It reconstructs a request from an
:class:`~zen.tools.ledger.objects.EvidenceReplay` descriptor, sends it (and its
negative control, if the oracle is differential) through an *injected*
:class:`ReplayTransport`, and returns what came back as a
:class:`~zen.validation.oracles.ReplayObservation`. It carries **no oracle logic
and no ground truth**: it never decides whether a response "confirms" anything —
that judgement stays with the quarantined oracle, which reads the observation this
returns. For that reason this module is deliberately **not** quarantined (it holds
no answer key), exactly like :mod:`zen.validation.quarantine` itself; the agent
and the optimizer may read it without learning a scoring function.

Why the injected transport: it keeps the replayer a pure, deterministic function
of its inputs, so it is unit-testable with a stub transport (no sockets, no
Docker, no tokens) while the runtime backs it with a real one — an HTTP client, or
the proxy's own replay session (``zen.tools.proxy``) when a captured exchange must
be re-sent with its original wire bytes. The replayer is medium-dispatching and
class-agnostic: it names ``http`` and opaque request fields, never a vulnerability
class.

Scope of the ``http`` replayer: it fills the observation's ``response_text`` (and
``negative_control_text`` when a control is supplied), which is what the
``canary_read`` and ``differential`` oracles read. Oracles that need an
out-of-band read-back (``effect_observed``) or a crash channel
(``crash_signature``) require their own transport and are out of scope here — an
HTTP re-send cannot observe them, so this replayer does not pretend to.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

from zen.validation.oracles import ReplayObservation


if TYPE_CHECKING:
    from zen.tools.ledger.objects import Evidence


@dataclass(frozen=True)
class ReplayRequest:
    """One reconstructed request to re-issue. Opaque fields, no class meaning."""

    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: str = ""


@dataclass(frozen=True)
class ReplayResponse:
    """What a transport observed for one request.

    ``reached`` lets a transport report "the surface did not answer" without
    raising (a raise is treated the same way); ``text`` is the fresh response body
    the oracle will read. The transport never interprets the body — it only
    carries it back.
    """

    status: int = 0
    text: str = ""
    reached: bool = True


class ReplayTransport(Protocol):
    """Sends a reconstructed request and reports the fresh response.

    The runtime supplies a concrete transport (a direct HTTP client, or a proxy
    replay session that re-sends the exact captured bytes). The replayer depends
    only on this shape, so it stays deterministic and testable with a stub.
    """

    def send(self, request: ReplayRequest) -> ReplayResponse:
        """Issue ``request`` live and return what came back."""
        ...


class HttpReplayer:
    """Re-executes an ``http`` evidence descriptor against the live surface.

    Satisfies the :class:`~zen.validation.library.Replayer` Protocol structurally,
    so it drops into :class:`~zen.validation.library.ValidatorLibrary` in place of
    the stub. Given a piece of :class:`~zen.tools.ledger.objects.Evidence`, it:

    1. reads the re-executable :class:`~zen.tools.ledger.objects.EvidenceReplay`
       descriptor and, for the ``http`` medium, rebuilds the request
       (method / url / headers / body) from its opaque ``inputs``;
    2. sends it through the injected transport and captures the **fresh** response;
    3. if the descriptor carries a ``negative_control``, sends that too and keeps
       its response, so a differential oracle has both sides to compare;
    4. returns a :class:`~zen.validation.oracles.ReplayObservation` whose
       ``response_text`` is what the surface answered *now* — not a stored quote.

    The oracle run over that observation is what confirms or rejects; this class
    only moves bytes. A request it cannot rebuild (no url, or a non-``http``
    medium) and a transport that fails both yield ``reached=False``, which the
    library treats as "did not reach the surface" — never a confirmation.
    """

    def __init__(self, transport: ReplayTransport) -> None:
        self._transport = transport

    def replay(self, evidence: Evidence) -> ReplayObservation:
        """Re-issue ``evidence``'s request live and report the fresh response."""
        descriptor = evidence.replay
        if descriptor.medium != "http":
            # This transport only speaks http; another medium is not reached here.
            return ReplayObservation(reached=False)

        request = self._build_request(descriptor.inputs)
        if request is None:
            return ReplayObservation(reached=False)

        response = self._safe_send(request)
        if response is None or not response.reached:
            return ReplayObservation(reached=False)

        negative_text = ""
        control = self._build_request(descriptor.negative_control)
        if control is not None:
            control_response = self._safe_send(control)
            if control_response is not None and control_response.reached:
                negative_text = control_response.text

        return ReplayObservation(
            reached=True,
            response_text=response.text,
            negative_control_text=negative_text,
        )

    def _safe_send(self, request: ReplayRequest) -> ReplayResponse | None:
        try:
            return self._transport.send(request)
        except Exception:  # noqa: BLE001 - a send that raises did not reach the surface
            return None

    @staticmethod
    def _build_request(inputs: dict[str, str]) -> ReplayRequest | None:
        """Rebuild a request from the opaque descriptor inputs, or ``None``.

        ``url`` is required (no url, nothing to send). ``method`` defaults to GET.
        ``headers`` is an optional JSON object stringified into the descriptor
        (the descriptor stores strings); a malformed value simply yields no
        headers rather than an error. ``body`` is passed through verbatim.
        """
        url = (inputs.get("url") or "").strip()
        if not url:
            return None
        method = (inputs.get("method") or "GET").strip().upper() or "GET"
        headers = _parse_headers(inputs.get("headers", ""))
        body = inputs.get("body", "")
        return ReplayRequest(method=method, url=url, headers=headers, body=body)


def _parse_headers(raw: str) -> dict[str, str]:
    """Parse a JSON-object header string into a dict; tolerant of junk/empty."""
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except (json.JSONDecodeError, TypeError, ValueError):
        return {}
    if not isinstance(parsed, dict):
        return {}
    return {str(key): str(value) for key, value in parsed.items()}


__all__ = ["HttpReplayer", "ReplayRequest", "ReplayResponse", "ReplayTransport"]
