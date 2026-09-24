"""OpenAI-compatible bridge backed by a Claude Code subscription session.

Zen drives its own agent loop (openai-agents SDK) and therefore needs a model
endpoint that emits tool calls for *Zen's* tools. The Claude Agent SDK is a
harness, not an endpoint: it runs its own loop and executes its own tools. This
module reconciles the two.

How it works:

  Zen  --POST /v1/chat/completions-->  bridge  --Agent SDK-->  Claude Code
                                                                      |
                                                        authenticates itself
                                                        against the user's plan

Zen's JSON function tools are registered as in-process MCP tools. When the
model calls one, the tool handler parks and the call is returned to Zen as an
OpenAI ``tool_calls`` response. Zen executes the tool for real and posts the
result on the next request, which unblocks the parked handler so the SDK
conversation continues exactly as if the tool had run locally.

That parking is what keeps this affordable: the Agent SDK conversation stays
alive for the life of a Zen agent, so each turn sends only the delta instead
of replaying the whole transcript. On a Pro plan, replay is the difference
between a scan finishing and hitting the 5-hour wall mid-run.

The bridge never reads, forwards, or stores credentials. Claude Code
authenticates itself via its own ``/login`` session; this process only speaks to
the local Agent SDK.

Model selection is pass-through. Whatever Zen puts in the request body's
``model`` field is what the SDK is asked for -- nothing is pinned or defaulted
here. Set it with ``ZEN_LLM``.

Run it:

    python -m zen.bridge --port 8787

Then point Zen at it:

    export ZEN_LLM="openai/claude-sonnet-4-6"
    export OPENAI_BASE_URL="http://127.0.0.1:8787/v1"
    export OPENAI_API_KEY="not-used"
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import logging
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
import tempfile


logger = logging.getLogger(__name__)


# Zen agents can sit idle while their siblings work; evict well after that.
# A deep-mode subagent can wait a long time between orchestrator messages, so
# this is deliberately generous -- evicting a live agent's session loses its
# conversation and forces a full re-establish on the next turn.
_SESSION_IDLE_TIMEOUT_S = float(os.environ.get("ZEN_BRIDGE_IDLE_TIMEOUT_S", "5400"))
# A single model turn, including thinking. Deep scan mode at high/xhigh effort
# produces genuinely long turns (exhaustive recon over a whole repo, chained
# exploitation), so this needs far more headroom than a quick scan.
_TURN_TIMEOUT_S = float(os.environ.get("ZEN_BRIDGE_TURN_TIMEOUT_S", "1800"))
_MCP_SERVER_NAME = "zen"
_MCP_PREFIX = f"mcp__{_MCP_SERVER_NAME}__"

# Effort levels the Agent SDK accepts. Note ``max`` sits above ``xhigh`` and has
# no equivalent in zen's own scale -- zen mirrors the OpenAI SDK's
# ``ReasoningEffort`` literal, whose pydantic model rejects "max" outright. So
# ``max`` is reachable only through ZEN_BRIDGE_EFFORT, which is exactly why
# this override exists.
_SDK_EFFORTS = ("low", "medium", "high", "xhigh", "max")

# zen scale -> Agent SDK scale. zen has two levels below "low" that the SDK
# doesn't; both floor to "low" rather than being dropped.
_ZEN_TO_SDK_EFFORT = {
    "none": "low",
    "minimal": "low",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "xhigh",
    "max": "max",
}


def _resolve_effort(payload: dict[str, Any]) -> str | None:
    """Pick the Agent SDK effort for this turn.

    Precedence: ``ZEN_BRIDGE_EFFORT`` (operator override, the only way to
    reach ``max``) > the ``reasoning_effort`` zen put in the request >
    unset, letting the SDK choose.

    An unrecognised override is logged and ignored rather than raised -- a typo
    in an env var shouldn't take down a running scan.
    """
    override = os.environ.get("ZEN_BRIDGE_EFFORT", "").strip().lower()
    if override:
        if override in _SDK_EFFORTS:
            return override
        mapped = _ZEN_TO_SDK_EFFORT.get(override)
        if mapped:
            return mapped
        logger.warning(
            "ignoring ZEN_BRIDGE_EFFORT=%r; expected one of %s",
            override,
            ", ".join(_SDK_EFFORTS),
        )

    requested = payload.get("reasoning_effort")
    if requested is None:
        reasoning = payload.get("reasoning")
        if isinstance(reasoning, dict):
            requested = reasoning.get("effort")
    if isinstance(requested, str):
        return _ZEN_TO_SDK_EFFORT.get(requested.strip().lower())
    return None


class BridgeError(RuntimeError):
    """A request could not be served."""


# --- OpenAI <-> Agent SDK translation ---------------------------------------


def _strip_prefix(tool_name: str) -> str:
    """SDK MCP tools are namespaced; Zen knows them by their bare name."""
    return tool_name[len(_MCP_PREFIX) :] if tool_name.startswith(_MCP_PREFIX) else tool_name


def _system_prompt(messages: list[dict[str, Any]]) -> str:
    parts = [
        _text_of(m.get("content"))
        for m in messages
        if m.get("role") == "system" and m.get("content")
    ]
    return "\n\n".join(p for p in parts if p)


def _text_of(content: Any) -> str:
    """OpenAI content is either a string or a list of typed parts."""
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        out: list[str] = []
        for part in content:
            if isinstance(part, str):
                out.append(part)
            elif isinstance(part, dict) and part.get("type") == "text":
                out.append(str(part.get("text", "")))
        return "\n".join(out)
    return str(content)


def _conversation_key(payload: dict[str, Any]) -> str:
    """Stable identity for one Zen agent's conversation.

    Zen is stateless over HTTP and resends the whole transcript every turn, so
    the session is keyed on the parts that don't change across turns: the system
    prompt, the opening user turn, and the tool surface.
    """
    messages = payload.get("messages") or []
    first_user = next(
        (_text_of(m.get("content")) for m in messages if m.get("role") == "user"),
        "",
    )
    tool_names = sorted(
        str((t.get("function") or {}).get("name", "")) for t in payload.get("tools") or []
    )
    digest = hashlib.sha256()
    digest.update(_system_prompt(messages).encode("utf-8", "replace"))
    digest.update(b"\x00")
    digest.update(first_user.encode("utf-8", "replace"))
    digest.update(b"\x00")
    digest.update("\x00".join(tool_names).encode("utf-8", "replace"))
    digest.update(b"\x00")
    digest.update(str(payload.get("model") or "").encode("utf-8", "replace"))
    return digest.hexdigest()


def _completion_envelope(model: str) -> dict[str, Any]:
    return {
        "id": f"chatcmpl-{uuid.uuid4().hex}",
        "object": "chat.completion",
        "created": int(time.time()),
        "model": model,
        "choices": [],
        "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
    }


def _as_tool_calls_response(model: str, calls: list[dict[str, Any]]) -> dict[str, Any]:
    body = _completion_envelope(model)
    body["choices"] = [
        {
            "index": 0,
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": c["id"],
                        "type": "function",
                        "function": {
                            "name": _strip_prefix(c["name"]),
                            "arguments": json.dumps(c["args"], ensure_ascii=False),
                        },
                    }
                    for c in calls
                ],
            },
            "finish_reason": "tool_calls",
        }
    ]
    return body


def _as_text_response(model: str, text: str) -> dict[str, Any]:
    body = _completion_envelope(model)
    body["choices"] = [
        {
            "index": 0,
            "message": {"role": "assistant", "content": text},
            "finish_reason": "stop",
        }
    ]
    return body


# --- session ----------------------------------------------------------------


@dataclass
class _Turn:
    """What a single model turn produced."""

    kind: str  # "tool" | "text" | "error"
    calls: list[dict[str, Any]] = field(default_factory=list)
    text: str = ""
    error: str = ""


class _Session:
    """One long-lived Agent SDK conversation, owned by a dedicated thread.

    The SDK is async and Zen's HTTP server is threaded, so each session runs
    its own event loop in its own thread and is driven with thread-safe queues.
    """

    def __init__(
        self,
        *,
        model: str,
        system_prompt: str,
        tools: list[dict[str, Any]],
        effort: str | None = None,
    ) -> None:
        self.model = model
        self.effort = effort
        self.last_used = time.monotonic()
        self._events: queue.Queue[_Turn] = queue.Queue()
        self._tool_results: queue.Queue[str] = queue.Queue()
        self._pending_calls: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._closed = False

        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._run_loop, name=f"zen-bridge-{model}", daemon=True
        )
        self._thread.start()
        self._client = self._submit(self._connect(system_prompt, tools, effort)).result(timeout=120)

    # -- thread / loop plumbing --

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self._loop)
        self._loop.run_forever()

    def _submit(self, coro: Any) -> Any:
        return asyncio.run_coroutine_threadsafe(coro, self._loop)

    # -- SDK wiring --

    def _make_tool(self, spec: dict[str, Any]) -> Any:
        from claude_agent_sdk import tool

        fn = spec.get("function") or {}
        name = str(fn.get("name") or "")
        description = str(fn.get("description") or name)
        # Pass Zen's JSON Schema through verbatim -- enums and required lists
        # included. The shorthand form drops them and the model then invents
        # values that fail Zen's pydantic validation.
        schema = fn.get("parameters") or {"type": "object", "properties": {}}

        async def handler(args: dict[str, Any]) -> dict[str, Any]:
            call_id = f"call_{uuid.uuid4().hex[:24]}"
            with self._lock:
                self._pending_calls.append({"id": call_id, "name": name, "args": args})
            # Hand the batch to the HTTP side and park until Zen answers.
            self._flush_pending()
            loop = asyncio.get_running_loop()
            result = await loop.run_in_executor(None, self._tool_results.get)
            return {"content": [{"type": "text", "text": result}]}

        return tool(name, description, schema)(handler)

    def _flush_pending(self) -> None:
        with self._lock:
            calls, self._pending_calls = self._pending_calls, []
        if calls:
            self._events.put(_Turn(kind="tool", calls=calls))

    async def _connect(
        self, system_prompt: str, tools: list[dict[str, Any]], effort: str | None
    ) -> Any:
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, create_sdk_mcp_server

        sdk_tools = [self._make_tool(t) for t in tools if (t.get("function") or {}).get("name")]
        server = create_sdk_mcp_server(name=_MCP_SERVER_NAME, version="1.1.1", tools=sdk_tools)
        # Write system prompt to a temp file to avoid ARG_MAX overflow.
        # The SDK passes --system-prompt as a CLI arg, which overflows
        # posix_spawn when the prompt is >100KB (deep scan mode).
        # --system-prompt-file reads from disk instead.
        self._prompt_file = None
        sp_option = None
        if system_prompt:
            self._prompt_file = tempfile.NamedTemporaryFile(
                mode="w", encoding="utf-8", suffix=".txt", delete=False, prefix="zen_prompt_"
            )
            self._prompt_file.write(system_prompt)
            self._prompt_file.close()
            sp_option = {"type": "file", "path": self._prompt_file.name}

        options = ClaudeAgentOptions(
            model=self.model,  # pass-through; nothing pinned
            system_prompt=sp_option,
            mcp_servers={_MCP_SERVER_NAME: server},
            allowed_tools=[f"{_MCP_PREFIX}{(t.get('function') or {}).get('name')}" for t in tools],
            tools=[],  # suppress Claude Code's own built-ins; Zen supplies the toolset
            setting_sources=None,  # ignore the user's project/user settings
            permission_mode="bypassPermissions",
            include_partial_messages=False,
            effort=effort,  # None -> SDK default
        )
        client = ClaudeSDKClient(options=options)
        await client.connect()
        return client

    async def _drain(self) -> None:
        """Consume one model turn, emitting a terminal event when it ends."""
        from claude_agent_sdk import AssistantMessage, ResultMessage, TextBlock

        text: list[str] = []
        try:
            async for msg in self._client.receive_response():
                if isinstance(msg, AssistantMessage):
                    text.extend(
                        block.text
                        for block in msg.content
                        if isinstance(block, TextBlock) and block.text
                    )
                elif isinstance(msg, ResultMessage):
                    break
        except Exception as exc:
            logger.debug("session drain failed", exc_info=True)
            self._events.put(_Turn(kind="error", error=f"{type(exc).__name__}: {exc}"))
            return
        # A turn that parked on a tool call already emitted its event.
        with self._lock:
            parked = bool(self._pending_calls)
        if not parked:
            self._events.put(_Turn(kind="text", text="".join(text).strip()))

    # -- public API --

    def send_user(self, text: str) -> _Turn:
        self.last_used = time.monotonic()
        self._submit(self._client.query(text))
        self._submit(self._drain())
        return self._await_turn()

    def send_tool_results(self, results: list[str]) -> _Turn:
        self.last_used = time.monotonic()
        for r in results:
            self._tool_results.put(r)
        return self._await_turn()

    def _await_turn(self) -> _Turn:
        try:
            return self._events.get(timeout=_TURN_TIMEOUT_S)
        except queue.Empty as exc:
            raise BridgeError(f"model turn exceeded {_TURN_TIMEOUT_S:.0f}s") from exc

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        # Clean up the temp prompt file
        if getattr(self, "_prompt_file", None) and self._prompt_file.name:
            with contextlib.suppress(OSError):
                os.unlink(self._prompt_file.name)
        with contextlib.suppress(Exception):
            self._submit(self._client.disconnect()).result(timeout=15)
        self._loop.call_soon_threadsafe(self._loop.stop)


class _SessionPool:
    """Maps Zen conversations to live Agent SDK sessions."""

    def __init__(self) -> None:
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    def get_or_create(self, key: str, payload: dict[str, Any]) -> tuple[_Session, bool]:
        self._evict_idle()
        with self._lock:
            existing = self._sessions.get(key)
            if existing is not None:
                return existing, False
        session = _Session(
            model=str(payload.get("model") or ""),
            system_prompt=_system_prompt(payload.get("messages") or []),
            tools=list(payload.get("tools") or []),
            effort=_resolve_effort(payload),
        )
        with self._lock:
            # Another thread may have raced us for the same Zen agent.
            racer = self._sessions.get(key)
            if racer is not None:
                session.close()
                return racer, False
            self._sessions[key] = session
        logger.info(
            "bridge session opened key=%s model=%s effort=%s",
            key[:12],
            session.model,
            session.effort or "(sdk default)",
        )
        return session, True

    def drop(self, key: str) -> None:
        with self._lock:
            session = self._sessions.pop(key, None)
        if session is not None:
            session.close()

    def _evict_idle(self) -> None:
        now = time.monotonic()
        with self._lock:
            stale = [
                k for k, s in self._sessions.items() if now - s.last_used > _SESSION_IDLE_TIMEOUT_S
            ]
            dead = [self._sessions.pop(k) for k in stale]
        for session in dead:
            session.close()
        if dead:
            logger.info("bridge evicted %d idle session(s)", len(dead))

    def close_all(self) -> None:
        with self._lock:
            sessions = list(self._sessions.values())
            self._sessions.clear()
        for session in sessions:
            session.close()


_POOL = _SessionPool()


# --- request handling -------------------------------------------------------


def _newest_turn_input(messages: list[dict[str, Any]]) -> tuple[str, list[str]]:
    """Return the newest input from Zen: either a user turn or tool results.

    Zen resends the full transcript each request; the session already holds
    everything before the last assistant turn, so only the tail is new.
    """
    tail: list[dict[str, Any]] = []
    for message in reversed(messages):
        if message.get("role") == "assistant":
            break
        tail.append(message)
    tail.reverse()

    tool_results = [_text_of(m.get("content")) for m in tail if m.get("role") == "tool"]
    if tool_results:
        return "tool", tool_results
    user_text = "\n\n".join(
        _text_of(m.get("content")) for m in tail if m.get("role") == "user"
    ).strip()
    return "user", [user_text]


def handle_chat_completion(payload: dict[str, Any]) -> dict[str, Any]:
    model = str(payload.get("model") or "")
    if not model:
        raise BridgeError("request is missing a 'model' -- set ZEN_LLM")
    messages = payload.get("messages") or []
    if not messages:
        raise BridgeError("request is missing 'messages'")

    key = _conversation_key(payload)
    session, is_new = _POOL.get_or_create(key, payload)
    kind, values = _newest_turn_input(messages)

    try:
        if kind == "tool" and not is_new:
            turn = session.send_tool_results(values)
        else:
            turn = session.send_user(values[0] if values else "")
    except BridgeError:
        _POOL.drop(key)
        raise

    if turn.kind == "error":
        _POOL.drop(key)
        raise BridgeError(turn.error)
    if turn.kind == "tool":
        return _as_tool_calls_response(model, turn.calls)
    return _as_text_response(model, turn.text)


class _Handler(BaseHTTPRequestHandler):
    server_version = "ZenClaudeBridge/1.0"

    def log_message(self, *args: Any) -> None:  # silence stderr access logging
        logger.debug("bridge http: " + args[0] if args else "bridge http")

    def _send_json(self, code: int, body: dict[str, Any]) -> None:
        raw = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_sse(self, body: dict[str, Any]) -> None:
        """Emit a non-streamed completion as a single SSE chunk.

        Zen streams turns, but the Agent SDK turn is already complete by the
        time we can answer, so one chunk plus [DONE] is faithful.
        """
        choice = body["choices"][0]
        chunk = {
            "id": body["id"],
            "object": "chat.completion.chunk",
            "created": body["created"],
            "model": body["model"],
            "choices": [
                {
                    "index": 0,
                    "delta": choice["message"],
                    "finish_reason": choice["finish_reason"],
                }
            ],
        }
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        for payload in (chunk,):
            self.wfile.write(f"data: {json.dumps(payload, ensure_ascii=False)}\n\n".encode())
        self.wfile.write(b"data: [DONE]\n\n")
        self.wfile.flush()

    def do_GET(self) -> None:
        if self.path.rstrip("/") in ("/v1/models", "/models"):
            self._send_json(200, {"object": "list", "data": []})
            return
        if self.path.rstrip("/") == "/health":
            self._send_json(200, {"status": "ok"})
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

        try:
            body = handle_chat_completion(payload)
        except BridgeError as exc:
            logger.warning("bridge request failed: %s", exc)
            self._send_json(502, {"error": {"message": str(exc), "type": "bridge_error"}})
            return
        except Exception as exc:
            logger.exception("bridge request crashed")
            self._send_json(500, {"error": {"message": f"{type(exc).__name__}: {exc}"}})
            return

        if payload.get("stream"):
            self._send_sse(body)
        else:
            self._send_json(200, body)


def serve(host: str = "127.0.0.1", port: int = 8787) -> None:
    httpd = ThreadingHTTPServer((host, port), _Handler)
    base = f"http://{host}:{port}/v1"
    logger.info("Zen Claude bridge listening on %s", base)
    print(f"Zen Claude bridge ready\n  OPENAI_BASE_URL={base}")  # noqa: T201
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        _POOL.close_all()
        httpd.server_close()
