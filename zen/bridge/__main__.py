"""``python -m zen.bridge`` -- run a local model-endpoint bridge.

Two backends:

  claude-code    OpenAI-compatible endpoint backed by a Claude Code
                 subscription session (Pro / Max). Default.
  top-tools-ai   OpenAI-compatible endpoint backed by Top Tools AI (GLM-5.2).
"""

from __future__ import annotations

import argparse
import logging
import sys


_BACKENDS = ("claude-code", "top-tools-ai")
_DEFAULT_PORTS = {"claude-code": 8787, "top-tools-ai": 8788}


def _run_top_tools_ai(host: str, port: int) -> int:
    from zen.bridge.top_tools_ai import BridgeError, resolve_config, serve

    try:
        resolve_config()
    except BridgeError as exc:
        print(f"{exc}", file=sys.stderr)  # noqa: T201
        return 1
    serve(host=host, port=port)
    return 0


def _run_claude_code(host: str, port: int) -> int:
    try:
        from claude_agent_sdk import ClaudeSDKClient  # noqa: F401
    except ImportError:
        print(  # noqa: T201
            "claude-agent-sdk is not installed.\n"
            "  pip install 'zen-agent[claude-sub]'   (or: pip install claude-agent-sdk)\n"
            "You also need Claude Code installed and logged in: claude /login",
            file=sys.stderr,
        )
        return 1

    from zen.bridge.claude_code import serve

    serve(host=host, port=port)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="python -m zen.bridge",
        description="Local OpenAI-compatible bridge for Zen.",
    )
    parser.add_argument(
        "--backend",
        choices=_BACKENDS,
        default="claude-code",
        help="Upstream to bridge to (default: claude-code).",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument(
        "--port",
        type=int,
        default=None,
        help="Listen port (default: 8787 claude-code, 8788 top-tools-ai).",
    )
    parser.add_argument("--verbose", "-v", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    port = args.port if args.port is not None else _DEFAULT_PORTS[args.backend]

    if args.backend == "top-tools-ai":
        return _run_top_tools_ai(args.host, port)
    return _run_claude_code(args.host, port)


if __name__ == "__main__":
    raise SystemExit(main())
