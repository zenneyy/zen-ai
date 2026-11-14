"""The error contract the local bridges share.

A bridge answers a failed request with the HTTP status that describes the
failure and an OpenAI-shaped error object. The client on the other side maps
the status to a typed error and reads ``type``, ``code`` and ``param`` from the
body, so each retry layer above it sees what actually happened: a credential
the upstream rejected arrives as a 401 or a 403, not as a gateway fault that
looks worth retrying.
"""

from __future__ import annotations

import re
from typing import Any


BAD_GATEWAY = 502
ERROR_DETAIL_MAX_CHARS = 2000

_REDACTED = "[redacted]"
_BEARER_CREDENTIAL = re.compile(r"(?i)\bbearer\s+[a-z0-9._~+/=-]{8,}")


def scrub(text: str, *credentials: str) -> str:
    """Return ``text`` with credentials removed, fit for a log line or an error body.

    Each value in ``credentials`` is removed wherever it appears, and so is
    anything shaped like a bearer credential, whoever it belonged to.
    """
    for credential in credentials:
        if credential:
            text = text.replace(credential, _REDACTED)
    return _BEARER_CREDENTIAL.sub(f"Bearer {_REDACTED}", text)


class BaseBridgeError(RuntimeError):
    """A request a bridge could not serve, with the status it answers with.

    ``status`` is the upstream's own status when the upstream reported the
    failure. The default, 502, is for a failure that has no upstream status:
    the upstream could not be reached, or it answered with something unusable.
    """

    def __init__(
        self,
        message: str,
        *,
        status: int = BAD_GATEWAY,
        error_type: str = "bridge_error",
        code: str | None = None,
        param: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.error_type = error_type
        self.code = code
        self.param = param

    def body(self) -> dict[str, Any]:
        """The response body: the error object an OpenAI client parses."""
        return {
            "error": {
                "message": str(self),
                "type": self.error_type,
                "code": self.code,
                "param": self.param,
            }
        }
