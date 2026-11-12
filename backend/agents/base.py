"""BaseAgent — common lifecycle, tool-grant declaration, and safe execution.

Each agent declares the narrow set of tools it is allowed to use. The
orchestrator records status/timing and catches failures so one agent's error
degrades that agent rather than aborting the scan.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod

from ..orchestrator.state import ScanContext, ScanState
from ..safety.errors import KillSwitchEngaged, SafetyError


class BaseAgent(ABC):
    name: str = "base"
    #: declared, enforced capability grant (documentation + runtime assertion)
    tool_grant: set[str] = set()

    @abstractmethod
    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        """Return a partial ScanState update."""
        ...

    async def execute(self, ctx: ScanContext, state: ScanState) -> dict:
        """Run the agent, recording status/timing and containing failures so one
        agent degrades rather than aborting the scan. Returns a partial
        ScanState update that always includes this agent's status."""
        started = time.monotonic()
        reqs0 = ctx.budget.used
        status = {"state": "running", "findings": 0}
        update: dict = {}
        try:
            await ctx.gate()   # hard-stop if killed; block here while paused
            await ctx.event("agent_start", f"{self.name} started", agent=self.name)
            update = await self.run(ctx, state)
            elapsed = time.monotonic() - started
            n = (len(update.get("candidates", [])) + len(update.get("validated", []))
                 + len(update.get("findings", [])))
            status.update(state="done", elapsed_s=round(elapsed, 2), findings=n,
                          requests=ctx.budget.used - reqs0)
            await ctx.event("agent_end", f"{self.name} finished ({n} items, {elapsed:.1f}s)",
                            agent=self.name, elapsed_s=round(elapsed, 2), items=n)
        except KillSwitchEngaged:
            status.update(state="stopped")
            await ctx.event("status", f"{self.name} stopped by kill switch", agent=self.name)
        except SafetyError as e:
            status.update(state="blocked", error=str(e))
            await ctx.event("error", f"{self.name} safety-blocked: {e}", agent=self.name)
        except Exception as e:  # degrade this agent, keep the scan alive
            ctx.killswitch.record_error()
            status.update(state="degraded", error=str(e)[:300])
            await ctx.event("error", f"{self.name} error: {e}", agent=self.name)
        update = dict(update)
        update["agent_status"] = {self.name: status}
        return update
