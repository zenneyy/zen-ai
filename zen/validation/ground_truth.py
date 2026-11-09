# ZEN-EVAL-QUARANTINE: do-not-feed-to-agent
"""Per-run ground truth the validator oracles rest on — quarantined.

The read/confidentiality oracle proves a protected read *actually occurred* by
planting a fresh, high-entropy **canary** inside the protected resource and then
requiring that canary to appear in the finding's re-executed response. The canary
is the ground truth: like the eval harness's sentinel, it is minted per run and
must never reach the agent's context, or the agent could fabricate a response
that merely contains it. So the minting lives here, behind the quarantine marker
at the top of this file, alongside the eval harness's own sentinel discipline.

Everything here is class-agnostic: a canary is opaque, high-entropy bytes with a
neutral prefix. It knows nothing about what resource it guards or what class of
read would expose it.
"""

from __future__ import annotations

import secrets


#: Neutral, generic prefix so a planted canary is recognisable in a replayed
#: response without any "flag"/"capture" terminology. 24 random bytes => 48 hex
#: chars of entropy; nothing an agent can brute-force or guess.
CANARY_PREFIX = "zcanary_"
_CANARY_BYTES = 24


def mint_canary() -> str:
    """Mint one high-entropy canary for a single protected resource / run."""
    return f"{CANARY_PREFIX}{secrets.token_hex(_CANARY_BYTES)}"


def is_canary(value: str) -> bool:
    """Whether a token has the canary shape (prefix + full-width hex)."""
    if not value.startswith(CANARY_PREFIX):
        return False
    body = value[len(CANARY_PREFIX) :]
    return len(body) == _CANARY_BYTES * 2 and all(c in "0123456789abcdef" for c in body)


__all__ = ["CANARY_PREFIX", "is_canary", "mint_canary"]
