"""Aegis safety core.

The only sanctioned path to the network. Import the guards from here.
"""

from .audit import AuditLog
from .errors import (
    AuthorizationError,
    BudgetExceeded,
    KillSwitchEngaged,
    SafetyError,
    ScopeViolation,
    SSRFBlocked,
)
from .killswitch import KillSwitch
from .ratelimit import Budget, RateLimiter
from .scope import ScopeSpec
from .ssrf import PinnedTarget, SSRFGuard

__all__ = [
    "AuditLog",
    "AuthorizationError",
    "Budget",
    "BudgetExceeded",
    "KillSwitch",
    "KillSwitchEngaged",
    "PinnedTarget",
    "RateLimiter",
    "SafetyError",
    "ScopeSpec",
    "ScopeViolation",
    "SSRFBlocked",
    "SSRFGuard",
]
