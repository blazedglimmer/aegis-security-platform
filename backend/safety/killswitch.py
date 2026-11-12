"""KillSwitch — a stop flag checked in the request path and between agent steps.

Flips on operator stop, budget exhaustion, or a run of consecutive errors
(a scanner stuck in a retry storm). Once engaged it stays engaged for the scan.
"""

from __future__ import annotations

from .errors import KillSwitchEngaged


class KillSwitch:
    def __init__(self, *, error_threshold: int = 25):
        self._engaged = False
        self._reason: str | None = None
        self._consecutive_errors = 0
        self._error_threshold = error_threshold

    @property
    def engaged(self) -> bool:
        return self._engaged

    @property
    def reason(self) -> str | None:
        return self._reason

    def engage(self, reason: str) -> None:
        if not self._engaged:
            self._engaged = True
            self._reason = reason

    def check(self) -> None:
        if self._engaged:
            raise KillSwitchEngaged(self._reason or "stopped")

    def record_success(self) -> None:
        self._consecutive_errors = 0

    def record_error(self) -> None:
        self._consecutive_errors += 1
        if self._consecutive_errors >= self._error_threshold:
            self.engage(f"aborted after {self._consecutive_errors} consecutive errors")
