"""Shared scan state (the LangGraph blackboard) and runtime context.

``ScanState`` is the typed dict LangGraph threads between nodes. ``ScanContext``
holds the live, non-serializable runtime (guards, clients, LLM, event sink) and
is passed to agents out-of-band. The WorkLedger prevents duplicate work across
agents.
"""

from __future__ import annotations

import asyncio
import operator
from dataclasses import dataclass, field
from typing import Annotated, Any, Awaitable, Callable, TypedDict

from ..config import Settings
from ..domain import Endpoint, Event, Finding, Lead, Tech
from ..safety.audit import AuditLog
from ..safety.killswitch import KillSwitch
from ..safety.ratelimit import Budget, RateLimiter
from ..safety.scope import ScopeSpec
from ..safety.ssrf import SSRFGuard
from ..tools.http_client import GuardedHttpClient
from ..tools.llm import LLMClient


def _merge_status(a: dict, b: dict) -> dict:
    out = dict(a or {})
    out.update(b or {})
    return out


class ScanState(TypedDict, total=False):
    # scalars (last write wins)
    scan_id: str
    authorization_id: str
    target_url: str
    profile: str
    selected_agents: list[str]
    status: str
    report_paths: dict[str, str]
    error: str | None
    # accumulating lists — reducers let parallel assessment agents append
    # concurrently without clobbering one another.
    tech: Annotated[list[dict], operator.add]
    endpoints: Annotated[list[dict], operator.add]
    candidates: Annotated[list[dict], operator.add]   # proposed by assessment agents
    validated: Annotated[list[dict], operator.add]    # confirmed by PoC validation
    findings: Annotated[list[dict], operator.add]     # canonical, written by analysis
    leads: Annotated[list[dict], operator.add]        # dynamic follow-up requests
    agent_status: Annotated[dict[str, dict], _merge_status]


class WorkLedger:
    """Dedup guard keyed by (agent, technique, endpoint)."""

    def __init__(self):
        self._done: set[tuple[str, str, str]] = set()
        self._lock = asyncio.Lock()

    async def claim(self, agent: str, technique: str, endpoint: str) -> bool:
        key = (agent, technique, endpoint.split("?")[0])
        async with self._lock:
            if key in self._done:
                return False
            self._done.add(key)
            return True


def _set_event() -> asyncio.Event:
    e = asyncio.Event()
    e.set()
    return e


EmitFn = Callable[[Event], Awaitable[None]]


@dataclass
class ScanContext:
    scan_id: str
    authorization_id: str
    target_url: str
    profile: str
    scope: ScopeSpec
    settings: Settings
    audit: AuditLog
    budget: Budget
    rate_limiter: RateLimiter
    killswitch: KillSwitch
    llm: LLMClient
    ledger: WorkLedger = field(default_factory=WorkLedger)
    emit: EmitFn | None = None
    #: set == running; cleared == paused. Checked at each agent boundary.
    pause_event: asyncio.Event = field(default_factory=lambda: _set_event())

    def pause(self) -> None:
        self.pause_event.clear()

    def resume(self) -> None:
        self.pause_event.set()

    async def gate(self) -> None:
        """Called at agent boundaries: hard-stop if killed, else block while paused."""
        self.killswitch.check()
        if not self.pause_event.is_set():
            await self.event("status", "scan paused", agent="orchestrator")
            await self.pause_event.wait()
            self.killswitch.check()
            await self.event("status", "scan resumed", agent="orchestrator")

    def new_client(self) -> GuardedHttpClient:
        """Mint a guarded HTTP client bound to this scan's safety core."""
        return GuardedHttpClient(
            scope=self.scope,
            ssrf=SSRFGuard(self.scope),
            rate_limiter=self.rate_limiter,
            budget=self.budget,
            audit=self.audit,
            killswitch=self.killswitch,
            scan_id=self.scan_id,
            timeout=self.settings and 20.0 or 20.0,
        )

    async def event(self, type: str, message: str = "", agent: str = "orchestrator", **data: Any) -> None:
        ev = Event(scan_id=self.scan_id, agent=agent, type=type, message=message, data=data)
        self.audit.append("event", {"type": type, "agent": agent, "message": message}, scan_id=self.scan_id)
        if self.emit:
            await self.emit(ev)
