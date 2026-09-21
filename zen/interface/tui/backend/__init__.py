"""Backend bridge for external TUI clients."""

from zen.interface.tui.backend.controller import TuiController
from zen.interface.tui.backend.server import TuiBackendServer


__all__ = ["TuiBackendServer", "TuiController"]
