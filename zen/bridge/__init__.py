"""Local model-endpoint bridges for Zen.

Currently one: :mod:`zen.bridge.claude_code`, an OpenAI-compatible endpoint
backed by a Claude Code subscription session.
"""

from zen.bridge.claude_code import BridgeError, handle_chat_completion, serve


__all__ = ["BridgeError", "handle_chat_completion", "serve"]
