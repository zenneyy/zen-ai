#!/bin/bash
# =============================================================================
# Zen — Claude Code Subscription (Pro / Max) Setup
# =============================================================================
# Routes Zen through a local bridge backed by your Claude Code session, so
# inference draws on your Claude subscription instead of a metered API key.
#
# Usage:
#   1. Start the bridge in one terminal:   python -m zen.bridge
#   2. In another terminal:                source ./setup-claude-sub.sh
#   3. Run a scan:                         zen --target ./your-app
#
# How it works:
#   The bridge exposes an OpenAI-compatible endpoint and drives the Claude
#   Agent SDK behind it. Claude Code authenticates itself via `claude /login`
#   — the bridge never reads or forwards your credentials.
#
# Prerequisites:
#   - Claude Code installed and logged in:  claude /login
#   - Bridge deps:                          pip install 'zen-agent[claude-sub]'
# =============================================================================

# ── CHANGE THIS IF YOU WANT A DIFFERENT MODEL ───────────────────────────────

MODEL="claude-opus-4-6"      # any model your Claude plan can serve
BRIDGE_PORT="8787"
REASONING="max"               # none | minimal | low | medium | high | xhigh

# ── DO NOT EDIT BELOW THIS LINE ─────────────────────────────────────────────

export ZEN_LLM="openai/${MODEL}"
export OPENAI_BASE_URL="http://127.0.0.1:${BRIDGE_PORT}/v1"
export OPENAI_API_BASE="http://127.0.0.1:${BRIDGE_PORT}/v1"
export OPENAI_API_KEY="bridge-local-no-key-needed"
export ZEN_REASONING_EFFORT="${REASONING}"

# Bridge-level effort override. The Claude bridge sets the Agent SDK's effort
# from this, which is also the only way to reach "max" (zen's own scale caps
# at xhigh). Keep it in sync with REASONING above; set to "max" for the ceiling.
export ZEN_BRIDGE_EFFORT="${ZEN_BRIDGE_EFFORT:-high}"

# High effort + deep scan mode produce genuinely long single turns (exhaustive
# recon across a whole repo, then chained exploitation). Give the bridge room so
# a slow-but-healthy turn isn't killed mid-flight and reported as a failure.
export ZEN_BRIDGE_TURN_TIMEOUT_S="${ZEN_BRIDGE_TURN_TIMEOUT_S:-1800}"
export ZEN_BRIDGE_IDLE_TIMEOUT_S="${ZEN_BRIDGE_IDLE_TIMEOUT_S:-5400}"

# REQUIRED. Zen injects LiteLLM's Anthropic prompt-cache directive whenever the
# model name contains "claude" (core/inputs.py::_prompt_cache_extra_args). The
# "openai/" prefix routes through the OpenAI SDK instead of LiteLLM, and
# AsyncCompletions.create() rejects the unknown kwarg with:
#   TypeError: unexpected keyword argument 'cache_control_injection_points'
# Nothing is lost by turning it off -- Claude Code does its own prompt caching
# server-side, so the client-side directive was never reaching a cache anyway.
export ZEN_PROMPT_CACHE=0

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  Zen → Claude Code subscription bridge                    ║"
echo "╠══════════════════════════════════════════════════════════════╣"
printf "║  Model:    %-48s║\n" "${MODEL}"
printf "║  Bridge:   %-48s║\n" "http://127.0.0.1:${BRIDGE_PORT}/v1"
printf "║  Effort:   %-48s║\n" "${REASONING}"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

if ! command -v claude >/dev/null 2>&1; then
  echo "WARNING: 'claude' not found on PATH. Install Claude Code and run: claude /login"
fi

if ! curl -sf "http://127.0.0.1:${BRIDGE_PORT}/health" >/dev/null 2>&1; then
  echo "NOTE: bridge not responding on port ${BRIDGE_PORT}."
  echo "      Start it first:  python -m zen.bridge --port ${BRIDGE_PORT}"
  echo ""
fi

echo "Run a deep scan:  zen --target ./your-app --scan-mode deep"
echo ""
echo "Deep + high effort is the most thorough setting — and the most quota-hungry."
echo "On a Pro plan expect to exhaust a 5-hour window; if you hit the wall mid-run:"
echo "  zen --resume <run-name>          # picks up where it stopped"
echo ""
echo "To stretch a run further, cap the fan-out rather than the depth:"
echo "  zen --target ./app --scan-mode deep --max-turns 60"
echo ""
echo "Cost figures in Zen reports are NOT real on a subscription — ignore them."
