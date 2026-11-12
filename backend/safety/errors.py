"""Safety-core exceptions.

These are raised *before* any packet leaves the process. They are deliberately
distinct types so the orchestrator, audit log, and dashboard can treat a
safety refusal differently from an ordinary network/tool error — a
ScopeViolation is never retried or "worked around", it is a hard stop.
"""

from __future__ import annotations


class SafetyError(Exception):
    """Base class for every hard safety refusal in the request path."""


class ScopeViolation(SafetyError):
    """Target host/IP/port/scheme is not inside the authorized scope."""


class SSRFBlocked(SafetyError):
    """Resolved address is private/reserved/metadata, or the request shape
    (scheme, credentials-in-URL, rebinding) is unsafe."""


class BudgetExceeded(SafetyError):
    """The per-scan request or time budget is exhausted."""


class KillSwitchEngaged(SafetyError):
    """Operator stop, or automatic abort on repeated errors/budget."""


class AuthorizationError(SafetyError):
    """No valid, unexpired authorization record covers this target."""
