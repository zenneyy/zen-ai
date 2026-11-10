"""The concrete live Replayer (Phase 2, item 2.2 — the deferred transport).

The validator library has always depended on a :class:`~zen.validation.library.Replayer`
*Protocol*, exercised only by a stub that returns a fixed observation. These prove
the **concrete** live replayer, :class:`zen.validation.replay.HttpReplayer`:

* fed a controlled transport, it reconstructs the request from a finding's
  re-executable descriptor and issues it live;
* the oracle then fires on the transport's **fresh** response — not on any value
  stored in the evidence (the decisive property: the canary lives only in what the
  re-execution returned, never in the recorded evidence);
* it drops into :class:`~zen.validation.library.ValidatorLibrary` in place of the
  stub, so it genuinely satisfies the Protocol;
* a reach-only re-execution (fresh response without the signal), a differential
  re-execution, and an unreachable surface all behave correctly.

Everything is class-agnostic and offline: a stub transport stands in for the live
HTTP client, so there is no socket, no Docker, and no token cost.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from zen.tools.ledger.objects import Evidence, EvidenceReplay, Finding
from zen.validation import (
    HttpReplayer,
    OracleExpectation,
    Replayer,
    ReplayRequest,
    ReplayResponse,
    ValidatorLibrary,
    verdict_confirms,
)
from zen.validation.ground_truth import mint_canary
from zen.validation.oracles import ReplayObservation, canary_read_oracle


@dataclass
class RecordingTransport:
    """A controlled transport: returns a scripted response, records what was sent.

    ``by_url`` maps a request url to the fresh response body to return for it, so a
    test can give the exploit url a canary-bearing response and a control url a
    clean one. Any unmapped url yields the ``default`` body.
    """

    by_url: dict[str, str]
    default: str = ""
    sent: list[ReplayRequest] = field(default_factory=list)

    def send(self, request: ReplayRequest) -> ReplayResponse:
        self.sent.append(request)
        return ReplayResponse(status=200, text=self.by_url.get(request.url, self.default))


def _http_evidence(
    *,
    inputs: dict[str, str],
    negative_control: dict[str, str] | None = None,
) -> Evidence:
    """An evidence record that carries a descriptor but NO canary of its own."""
    return Evidence(
        id="e1",
        kind="proxy_exchange",
        evidence_refs=["req-101"],
        summary="captured exchange (contains no protected value)",
        replay=EvidenceReplay(
            medium="http",
            inputs=inputs,
            negative_control=negative_control or {},
        ),
    )


# ── the Protocol is satisfied by a concrete implementation ───────────────────


def test_http_replayer_satisfies_the_replayer_protocol() -> None:
    replayer: Replayer = HttpReplayer(RecordingTransport(by_url={}))
    assert callable(replayer.replay)


# ── THE deferred property: the oracle fires on the FRESH response ────────────


def test_oracle_fires_on_the_fresh_response_not_on_stored_evidence() -> None:
    """The decisive test. The canary exists ONLY in the transport's fresh response;
    the recorded evidence never contains it. A confirmation therefore proves a live
    re-execution recovered the value, not that the evidence quoted it."""
    canary = mint_canary()
    url = "http://target.local/api/resource"
    evidence = _http_evidence(inputs={"method": "GET", "url": url})

    # Precondition: the canary is nowhere in the stored evidence.
    assert canary not in evidence.model_dump_json()

    transport = RecordingTransport(by_url={url: f"HTTP/1.1 200 OK\nsecret={canary}\n"})
    verdict = ValidatorLibrary(HttpReplayer(transport)).validate(
        Finding(id="f1"),
        evidence,
        OracleExpectation(shape="canary_read", value=canary),
        author="live-validator",
    )

    # The request was reconstructed from the descriptor and issued live...
    assert len(transport.sent) == 1
    assert transport.sent[0].method == "GET"
    assert transport.sent[0].url == url
    # ...and the oracle confirmed on the re-executed response.
    assert verdict.passed is True and verdict.reach_only is False
    assert verdict.oracle_signal["canary"] == canary
    assert verdict_confirms(verdict) is True


def test_replayer_returns_a_real_observation_the_oracle_reads_directly() -> None:
    """Same property, one layer down: the observation's response_text IS the fresh
    transport response, and the oracle run over it directly fires."""
    canary = mint_canary()
    url = "http://target/export"
    fresh = f"<html>…{canary}…</html>"
    transport = RecordingTransport(by_url={url: fresh})

    observation = HttpReplayer(transport).replay(
        _http_evidence(inputs={"method": "GET", "url": url})
    )

    assert isinstance(observation, ReplayObservation)
    assert observation.reached is True
    assert observation.response_text == fresh
    assert canary_read_oracle(observation, canary).present is True


# ── reconstruction fidelity: method / headers / body all come through ────────


def test_replayer_reconstructs_method_headers_and_body() -> None:
    url = "http://target/api/preview"
    transport = RecordingTransport(by_url={url: "ok"})
    evidence = _http_evidence(
        inputs={
            "method": "post",
            "url": url,
            "headers": '{"Authorization": "Bearer t0ken", "X-Scope": "tenant-7"}',
            "body": '{"target":"http://169.254.169.254/"}',
        }
    )

    HttpReplayer(transport).replay(evidence)

    sent = transport.sent[0]
    assert sent.method == "POST"  # normalised
    assert sent.url == url
    assert sent.headers == {"Authorization": "Bearer t0ken", "X-Scope": "tenant-7"}
    assert sent.body == '{"target":"http://169.254.169.254/"}'


# ── reached-vs-performed, now driven by a real re-execution ──────────────────


def test_a_fresh_response_without_the_signal_is_reach_only() -> None:
    canary = mint_canary()
    url = "http://target/export"
    # The surface answers (reached), but the fresh body carries no protected value.
    transport = RecordingTransport(by_url={url: "HTTP/1.1 200 OK\n<index page>"})
    verdict = ValidatorLibrary(HttpReplayer(transport)).validate(
        Finding(id="f1"),
        _http_evidence(inputs={"method": "GET", "url": url}),
        OracleExpectation(shape="canary_read", value=canary),
        author="live-validator",
    )
    assert verdict.passed is False and verdict.reach_only is True
    assert "REACH-ONLY" in verdict.detail


def test_differential_re_execution_sends_both_sides_and_requires_the_difference() -> None:
    marker = mint_canary()
    exploit_url = "http://target/admin?as=victim"
    control_url = "http://target/admin"
    transport = RecordingTransport(
        by_url={exploit_url: f"role=admin {marker}", control_url: "role=guest"},
    )
    evidence = _http_evidence(
        inputs={"method": "GET", "url": exploit_url},
        negative_control={"method": "GET", "url": control_url},
    )

    verdict = ValidatorLibrary(HttpReplayer(transport)).validate(
        Finding(id="f1"),
        evidence,
        OracleExpectation(shape="differential", value=marker),
        author="live-validator",
    )

    # Both the exploit request and its negative control were issued live.
    sent_urls = {r.url for r in transport.sent}
    assert sent_urls == {exploit_url, control_url}
    # The marker appeared under the exploit but not the control: a real difference.
    assert verdict.passed is True and verdict.reach_only is False


# ── honest failure modes: nothing to send, or the surface is down ────────────


def test_an_unreachable_surface_yields_no_confirmation() -> None:
    canary = mint_canary()

    @dataclass
    class DeadTransport:
        def send(self, request: ReplayRequest) -> ReplayResponse:  # noqa: ARG002
            raise ConnectionError("target is down")

    verdict = ValidatorLibrary(HttpReplayer(DeadTransport())).validate(
        Finding(id="f1"),
        _http_evidence(inputs={"method": "GET", "url": "http://target/export"}),
        OracleExpectation(shape="canary_read", value=canary),
        author="live-validator",
    )
    assert verdict.passed is False
    assert verdict_confirms(verdict) is False


def test_a_descriptor_with_no_url_or_wrong_medium_does_not_reach() -> None:
    transport = RecordingTransport(by_url={})
    replayer = HttpReplayer(transport)

    # No url to rebuild a request from.
    no_url = replayer.replay(_http_evidence(inputs={"method": "GET"}))
    assert no_url.reached is False

    # A non-http medium is not this transport's to replay.
    other = Evidence(id="e2", kind="command_exec", replay=EvidenceReplay(medium="command"))
    assert replayer.replay(other).reached is False

    # Nothing was sent in either case.
    assert transport.sent == []
