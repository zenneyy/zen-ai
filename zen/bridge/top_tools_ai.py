"""OpenAI-compatible bridge backed by Top Tools AI (GLM-5.2).

Zen drives its own agent loop (openai-agents SDK) and expects a model
endpoint that emits OpenAI-style tool calls for *Zen's* tools. Top Tools AI
already speaks OpenAI's chat-completions wire format, so unlike the Claude
bridge we do not need to host an Agent SDK conversation -- we only need to:

  1. Terminate TLS locally and re-authenticate with the real Top Tools AI key,
     so zen never sees the upstream credentials and never has to wrestle with
     LiteLLM provider routing for an unmapped model id.
  2. Translate zen's reasoning effort (none|minimal|low|medium|high|xhigh)
     into the two values GLM-5.2 actually accepts: ``off`` or ``deep``.
  3. Forward tool calls and tool results verbatim in both directions.
  4. Speak the OpenAI streaming wire format back to zen so it integrates as a
     normal ``openai/<model>`` provider.

This eliminates the 403s zen hits when pointed at the upstream directly:
those come from LiteLLM trying to validate/route an unmapped ``GLM-5.2`` model
id through provider-specific auth paths. By presenting a plain local OpenAI
endpoint, the openai-agents SDK talks native OpenAI and never invokes LiteLLM
routing for the model.

Run it:

    python -m zen.bridge.top_tools_ai --port 8788
    python -m zen.bridge --backend top-tools-ai      # equivalent

Then point Zen at it:

    export ZEN_LLM="openai/GLM-5.2"
    export OPENAI_BASE_URL="http://127.0.0.1:8788/v1"
    export OPENAI_API_KEY="bridge-local-no-key-needed"
    # See setup-top-tools-ai.sh
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib import parse as urlparse

import requests
from requests.adapters import HTTPAdapter


if TYPE_CHECKING:
    from collections.abc import Iterator


logger = logging.getLogger(__name__)


# Zen reasoning efforts are: none | minimal | low | medium | high | xhigh.
# GLM-5.2 only accepts reasoning_effort = "off" | "deep" (per /v1/models), and
# deep is what we want for security work -- so everything except an explicit
# off/none maps to deep.
def _to_top_tools_reasoning(effort: str | None) -> str:
    if effort is None or effort.strip().lower() in ("", "none", "off"):
        return "off"
    return "deep"


def _upstream_reasoning(payload: dict[str, Any]) -> str:
    """Resolve the reasoning value to send upstream. Always ``off`` or ``deep``.

    Zen only attaches a reasoning field when ``model_supports_reasoning()`` is
    true, and that check consults LiteLLM's ``model_cost`` registry. GLM-5.2 is
    not in that registry, so zen silently drops ``ZEN_REASONING_EFFORT`` and
    the request reaches the bridge with no reasoning field at all. We fall back
    to ``ZEN_BRIDGE_DEFAULT_REASONING`` (default ``deep``) so the operator's
    intent survives zen's registry gap.

    Every path funnels through :func:`_to_top_tools_reasoning`, so an operator
    who sets a zen-scale value like ``high`` gets a valid ``deep`` upstream
    rather than a 400 from an unrecognised effort name.
    """
    # ZEN_BRIDGE_EFFORT is the shared override across both bridges, so one
    # variable drives effort regardless of which backend is running.
    # ZEN_BRIDGE_DEFAULT_REASONING stays supported as the older, bridge-
    # specific name.
    override = os.environ.get("ZEN_BRIDGE_EFFORT", "").strip()
    if override:
        return _to_top_tools_reasoning(override)
    effort = _reasoning_effort_from_request(payload)
    if effort is None:
        effort = os.environ.get("ZEN_BRIDGE_DEFAULT_REASONING", "deep")
    return _to_top_tools_reasoning(effort)


class BridgeError(RuntimeError):
    """A request could not be served."""


# --- configuration ---------------------------------------------------------


_DEFAULT_BASE_URL = "https://top-tools-ai.com/api/v1"
_DEFAULT_MODEL = "qwen3.8-max"
_DEFAULT_PORT = 8788

# Deep reasoning on a long agentic turn is slow; a quick-scan default would cut
# healthy turns off mid-flight and surface them to zen as bridge failures.
_UPSTREAM_TIMEOUT_S = float(os.environ.get("ZEN_BRIDGE_UPSTREAM_TIMEOUT_S", "1800"))

# Request fields we forward upstream. An allowlist rather than a denylist: zen
# and the openai-agents SDK attach internal fields the upstream rejects, so
# anything not listed here is dropped deliberately. ``reasoning``/
# ``reasoning_effort`` are absent on purpose -- we compute those ourselves.
_PASSTHROUGH_FIELDS = (
    "messages",
    "tools",
    "tool_choice",
    "parallel_tool_calls",
    "max_tokens",
    "max_completion_tokens",
    "temperature",
    "top_p",
    "stop",
    "stream_options",
    "response_format",
    "seed",
    "n",
    "presence_penalty",
    "frequency_penalty",
    "logit_bias",
    "user",
)


def resolve_config() -> dict[str, str]:
    """Read upstream config from env, falling back to defaults.

    Precedence: explicit env > ``~/.ultron/providers.json`` > built-in default.
    Reading the key from the ultron providers file keeps the bridge in sync with
    whatever key the operator is currently using in ultron itself. Resolved per
    request, so rotating the key there takes effect without a restart.
    """
    base_url = os.environ.get("TOP_TOOLS_AI_BASE_URL", _DEFAULT_BASE_URL)
    api_key = os.environ.get("TOP_TOOLS_AI_API_KEY", "")
    if not api_key:
        api_key = _load_key_from_ultron_providers()
    if not api_key:
        raise BridgeError(
            "No Top Tools AI API key found. Set TOP_TOOLS_AI_API_KEY or add a "
            "'top-tools-ai' entry to ~/.ultron/providers.json."
        )
    return {"base_url": _validated_base_url(base_url), "api_key": api_key}


def _validated_base_url(base_url: str) -> str:
    """Reject non-HTTP(S) upstreams.

    ``TOP_TOOLS_AI_BASE_URL`` is operator-supplied, and an HTTP client will
    happily open ``file://`` and other schemes. Constraining it here means a stray or
    injected value can't turn an upstream call into a local file read.
    """
    cleaned = base_url.rstrip("/")
    scheme = urlparse.urlsplit(cleaned).scheme.lower()
    if scheme not in ("http", "https"):
        raise BridgeError(f"TOP_TOOLS_AI_BASE_URL must be an http(s) URL, got scheme {scheme!r}")
    return cleaned


def _load_key_from_ultron_providers() -> str:
    """Pull the first top-tools-ai key from the ultron providers file."""
    for path in (Path("~/.ultron/providers.json").expanduser(),):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        for provider in data.get("providers") or []:
            if provider.get("type") == "top-tools-ai":
                keys = provider.get("apiKeys") or []
                if keys:
                    return str(keys[0])
    return ""


# --- upstream call ---------------------------------------------------------


# Transient upstream failures are common on this provider (a 25-minute scan hit
# 5 connection timeouts, three 502s and a 504). Left to zen, each one triggers
# ``DEFAULT_MODEL_RETRY`` -- exponential backoff from 2s up to 90s -- so a
# one-second blip costs a minute of dead time. Retrying here, fast and bounded,
# means zen usually never sees the failure at all.
_RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
_MAX_ATTEMPTS = int(os.environ.get("ZEN_BRIDGE_MAX_ATTEMPTS", "3"))
_RETRY_BASE_DELAY_S = float(os.environ.get("ZEN_BRIDGE_RETRY_BASE_S", "1.0"))


def _retry_delay(attempt: int) -> float:
    """1s, 2s, 4s ... -- deliberately far tighter than zen's 2s..90s ladder."""
    return _RETRY_BASE_DELAY_S * (2 ** (attempt - 1))


# A pooled session, shared across bridge threads. Opening a fresh TCP+TLS
# connection per request costs ~2s against this upstream -- measured at 4.06s
# median on a fresh connection vs 2.01s on a reused one. Zen issues hundreds
# of calls per scan, so keep-alive is the single largest saving available on
# our side of the wire. ``requests`` is already a zen dependency and its
# HTTPAdapter pools connections per host; the Session is thread-safe for the
# plain request/response use here.
_SESSION: Any = None
_SESSION_LOCK = threading.Lock()
_POOL_SIZE = int(os.environ.get("ZEN_BRIDGE_POOL_SIZE", "32"))


def _session() -> Any:
    """Return the shared pooled session, creating it on first use."""
    global _SESSION  # noqa: PLW0603 - module-level singleton by design
    if _SESSION is not None:
        return _SESSION
    with _SESSION_LOCK:
        if _SESSION is None:
            sess = requests.Session()
            # Zen fans out across parallel subagents; size the pool so
            # concurrent turns don't fall back to fresh connections.
            adapter = HTTPAdapter(
                pool_connections=_POOL_SIZE,
                pool_maxsize=_POOL_SIZE,
                max_retries=0,  # retries are handled by _open_upstream
            )
            sess.mount("https://", adapter)
            sess.mount("http://", adapter)
            _SESSION = sess
    return _SESSION


def _open_upstream(
    *,
    url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
    stream: bool,
) -> Any:
    """POST upstream over the pooled session, retrying transient failures.

    Returns the live ``requests.Response``; the caller owns closing it. Raises
    ``BridgeError`` only once every attempt is used, so zen's own 2s..90s
    backoff engages just for failures that are actually persistent.

    A non-retryable status (401/403/400 ...) is returned as-is rather than
    raised, so callers can surface the upstream's own error body.
    """
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "Accept": "text/event-stream" if stream else "application/json",
    }
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")

    last_detail = ""
    for attempt in range(1, _MAX_ATTEMPTS + 1):
        try:
            resp = _session().post(url, data=body, headers=headers, timeout=timeout, stream=stream)
        except requests.RequestException as exc:
            last_detail = f"{type(exc).__name__}: {exc}"
        else:
            if resp.status_code not in _RETRY_STATUSES:
                return resp
            last_detail = f"HTTP {resp.status_code}"
            resp.close()

        if attempt < _MAX_ATTEMPTS:
            delay = _retry_delay(attempt)
            logger.info(
                "upstream %s (attempt %d/%d); retrying in %.1fs",
                last_detail,
                attempt,
                _MAX_ATTEMPTS,
                delay,
            )
            time.sleep(delay)

    raise BridgeError(f"upstream failed after {_MAX_ATTEMPTS} attempts: {last_detail}")


def _post_upstream(
    *,
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
) -> tuple[int, dict[str, Any] | None, str]:
    """POST to Top Tools AI and return (status, json_body_or_None, raw_text).

    Goes over the shared pooled session, so the TCP+TLS handshake is paid once
    per connection rather than once per call. Streaming responses are handled
    separately in :func:`_stream_upstream`.
    """
    resp = _open_upstream(
        url=f"{base_url}/chat/completions",
        api_key=api_key,
        payload=payload,
        timeout=timeout,
        stream=False,
    )
    with resp:
        status = resp.status_code
        text = resp.text

    if not text:
        return status, None, ""
    try:
        return status, json.loads(text), text
    except json.JSONDecodeError:
        return status, None, text


def _stream_upstream(
    *,
    base_url: str,
    api_key: str,
    payload: dict[str, Any],
    timeout: float,
):
    """POST to Top Tools AI with stream=true and yield raw SSE chunks.

    Yields ``(event_type, parsed_json_or_None, raw_line)`` per SSE message.
    The caller rewrites model/usage fields and re-emits on the zen side.
    """
    # Retry happens only while opening the connection -- once frames have been
    # yielded downstream a retry would duplicate content, so a mid-stream drop
    # is still surfaced to zen.
    resp = _open_upstream(
        url=f"{base_url}/chat/completions",
        api_key=api_key,
        payload=payload,
        timeout=timeout,
        stream=True,
    )
    if resp.status_code != 200:
        detail = resp.text[:500]
        resp.close()
        raise BridgeError(f"upstream returned {resp.status_code}: {detail}")

    with resp:
        buf = b""
        for chunk in resp.iter_content(chunk_size=4096):
            if not chunk:
                continue
            buf += chunk
            while b"\n\n" in buf:
                raw_event, buf = buf.split(b"\n\n", 1)
                for line in raw_event.split(b"\n"):
                    if not line.startswith(b"data:"):
                        continue
                    data = line[5:].strip()
                    if not data:
                        continue
                    text = data.decode("utf-8", errors="replace")
                    if text == "[DONE]":
                        yield ("done", None, text)
                        continue
                    try:
                        yield ("data", json.loads(text), text)
                    except json.JSONDecodeError:
                        yield ("data", None, text)


# --- request handling -----------------------------------------------------


def _reasoning_effort_from_request(payload: dict[str, Any]) -> str | None:
    """Extract the reasoning effort zen sent, if any.

    The openai-agents SDK puts it either at top-level ``reasoning_effort`` or
    inside ``reasoning: {effort: ...}``. We accept both.
    """
    if "reasoning_effort" in payload:
        return str(payload.get("reasoning_effort") or "none")
    reasoning = payload.get("reasoning")
    if isinstance(reasoning, dict):
        return str(reasoning.get("effort") or "none")
    return None


def _build_upstream_payload(payload: dict[str, Any]) -> dict[str, Any]:
    """Translate a zen OpenAI request into a Top Tools AI request.

    We pass model, messages, tools and tool_choice through unchanged. We force
    ``stream=False`` here; the streaming path is handled by the HTTP handler
    when zen asks for SSE. We translate reasoning_effort to GLM-5.2's accepted
    values. We drop zen-only fields the upstream rejects.
    """
    upstream: dict[str, Any] = {
        "model": payload.get("model") or _DEFAULT_MODEL,
        "messages": payload.get("messages") or [],
        "stream": False,
        "reasoning_effort": _upstream_reasoning(payload),
    }
    # Forward the rest of the standard OpenAI request surface untouched. This
    # matters beyond convenience: zen sets ``parallel_tool_calls=False`` in
    # ``make_model_settings`` because its agent loop executes one tool at a
    # time, and it sets ``stream_options.include_usage`` to drive cost/usage
    # bookkeeping. Dropping either silently changes behaviour zen relies on.
    for field in _PASSTHROUGH_FIELDS:
        value = payload.get(field)
        if field in payload and value is not None:
            upstream[field] = value

    _debug_log(
        "ZEN_BRIDGE_UPSTREAM_LOG",
        {
            "in_reasoning_effort": payload.get("reasoning_effort"),
            "in_reasoning": payload.get("reasoning"),
            "translated_effort": upstream["reasoning_effort"],
            "defaulted": _reasoning_effort_from_request(payload) is None,
            "upstream_model": upstream["model"],
            "stream": upstream["stream"],
            "forwarded": sorted(upstream.keys()),
        },
    )
    return upstream


def _debug_log(env_var: str, record: dict[str, Any]) -> None:
    """Append a JSONL debug record when ``env_var`` names a log file."""
    path = os.environ.get(env_var, "")
    if not path:
        return
    try:
        with Path(path).open("a", encoding="utf-8") as fh:
            fh.write(json.dumps({"ts": time.time(), **record}, ensure_ascii=False) + "\n")
    except OSError:
        logger.debug("could not write debug log to %s", path, exc_info=True)


def handle_chat_completion(payload: dict[str, Any]) -> dict[str, Any]:
    """Non-streaming completion. Returns an OpenAI chat.completion object."""
    config = resolve_config()
    upstream_payload = _build_upstream_payload(payload)
    status, body, text = _post_upstream(
        base_url=config["base_url"],
        api_key=config["api_key"],
        payload=upstream_payload,
        timeout=_UPSTREAM_TIMEOUT_S,
    )
    if status != 200 or body is None:
        detail = text[:500] if text else f"status {status}"
        raise BridgeError(f"upstream returned {status}: {detail}")
    # The upstream response is already OpenAI-shaped; pass it through. We only
    # normalise the model field so zen's bookkeeping matches what it asked
    # for, and ensure 'usage' exists (some providers omit it on errors).
    body.setdefault("model", payload.get("model") or _DEFAULT_MODEL)
    body.setdefault("usage", {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0})
    return body


def handle_chat_completion_stream(payload: dict[str, Any]) -> Iterator[str]:
    """Streaming completion. Yields SSE frames as they arrive from upstream.

    This is a generator on purpose. Buffering the whole stream and returning one
    string would mean zen sees nothing until the turn is fully generated --
    which on deep reasoning is minutes of apparent hang, and defeats the live
    output zen's TUI renders from ``stream.stream_events()``.

    The upstream already emits OpenAI ``chat.completion.chunk`` objects, so we
    only normalise the model id to what zen asked for.
    """
    config = resolve_config()
    upstream_payload = _build_upstream_payload(payload)
    upstream_payload["stream"] = True
    requested_model = payload.get("model") or _DEFAULT_MODEL

    for kind, parsed, raw in _stream_upstream(
        base_url=config["base_url"],
        api_key=config["api_key"],
        payload=upstream_payload,
        timeout=_UPSTREAM_TIMEOUT_S,
    ):
        if kind == "done":
            yield "data: [DONE]\n\n"
            return
        if parsed is None:
            # Unparseable upstream line -- pass through verbatim.
            yield f"data: {raw}\n\n"
            continue
        parsed.setdefault("model", requested_model)
        yield f"data: {json.dumps(parsed, ensure_ascii=False)}\n\n"


# --- HTTP server ----------------------------------------------------------


class _Handler(BaseHTTPRequestHandler):
    server_version = "ZenTopToolsAiBridge/1.0"

    def log_message(self, fmt: str = "", *args: Any) -> None:
        logger.debug("bridge http: %s", fmt % args if args else fmt)

    def _send_json(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_sse_stream(self, frames: Iterator[str]) -> None:
        """Stream SSE frames to the client, flushing each as it arrives.

        No ``Content-Length``: the body length isn't known up front, and the
        handler's HTTP/1.0 response closes the connection to delimit the body.
        The first frame is pulled *before* the headers go out so an upstream
        failure still surfaces as a clean 502 rather than a 200 with an empty
        body.
        """
        try:
            first = next(frames)
        except StopIteration:
            first = ""

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Connection", "close")
        self.end_headers()

        for frame in (first, *frames) if first else frames:
            self.wfile.write(frame.encode("utf-8"))
            self.wfile.flush()

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self._send_json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": _DEFAULT_MODEL,
                            "object": "model",
                            "created": int(time.time()),
                            "owned_by": "top-tools-ai",
                        }
                    ],
                },
            )
            return
        if self.path.rstrip("/") == "/health":
            try:
                resolve_config()
            except BridgeError as exc:
                self._send_json(503, {"status": "misconfigured", "error": str(exc)})
                return
            self._send_json(200, {"status": "ok", "upstream": _DEFAULT_BASE_URL})
            return
        self._send_json(404, {"error": {"message": "not found"}})

    def do_POST(self) -> None:
        if self.path.rstrip("/") not in ("/v1/chat/completions", "/chat/completions"):
            self._send_json(404, {"error": {"message": "not found"}})
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
            payload = json.loads(self.rfile.read(length) or b"{}")
        except (ValueError, json.JSONDecodeError) as exc:
            self._send_json(400, {"error": {"message": f"bad request body: {exc}"}})
            return

        want_stream = bool(payload.get("stream"))
        _debug_log(
            "ZEN_BRIDGE_REQUEST_LOG",
            {
                "model": payload.get("model"),
                "reasoning_effort": payload.get("reasoning_effort"),
                "reasoning": payload.get("reasoning"),
                "stream": want_stream,
                "tool_count": len(payload.get("tools") or []),
                "message_count": len(payload.get("messages") or []),
                "top_level_keys": sorted(payload.keys()),
            },
        )
        try:
            if want_stream:
                self._send_sse_stream(handle_chat_completion_stream(payload))
            else:
                self._send_json(200, handle_chat_completion(payload))
        except BridgeError as exc:
            logger.warning("bridge request failed: %s", exc)
            self._send_json(502, {"error": {"message": str(exc), "type": "bridge_error"}})
        except Exception as exc:
            logger.exception("bridge request crashed")
            self._send_json(500, {"error": {"message": f"{type(exc).__name__}: {exc}"}})


def serve(host: str = "127.0.0.1", port: int = _DEFAULT_PORT) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    base = f"http://{host}:{port}/v1"
    logger.info("Zen Top Tools AI bridge listening on %s", base)
    print(  # noqa: T201
        f"Zen Top Tools AI bridge ready\n"
        f"  OPENAI_BASE_URL={base}\n"
        f"  upstream={_DEFAULT_BASE_URL}\n"
        f"  model={_DEFAULT_MODEL}"
    )
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m zen.bridge.top_tools_ai",
        description="OpenAI-compatible endpoint backed by Top Tools AI (GLM-5.2).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=_DEFAULT_PORT)
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    try:
        resolve_config()
    except BridgeError as exc:
        print(f"{exc}", file=sys.stderr)  # noqa: T201
        return 1

    serve(host=args.host, port=args.port)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
