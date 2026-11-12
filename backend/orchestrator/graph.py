"""Orchestrator — the LangGraph state machine that drives a scan.

Topology:

    START → authorize → recon → ┬→ web_vuln ┐
                                 ├→ authz    ┼→ validate → analyze → report → END
                                 └→ api      ┘

``recon`` fans out (in parallel) to the *selected* assessment agents; they
fan in to ``validate``. State reducers (see ``state.py``) let the parallel
branches append findings concurrently. A native asyncio runner implementing the
identical topology is provided as a fallback and for environments without
LangGraph; both call the same agent code.
"""

from __future__ import annotations

import asyncio
from typing import Callable

from ..agents.analysis import AnalysisAgent
from ..agents.api import ApiAgent
from ..agents.authz import AuthzAgent
from ..agents.exploit import ExploitValidationAgent
from ..agents.recon import ReconAgent
from ..agents.reporting import ReportingAgent
from ..agents.webvuln import WebVulnAgent
from ..domain import ScanStatus
from .state import ScanContext, ScanState

ASSESSMENT = {"web_vuln": WebVulnAgent, "authz": AuthzAgent, "api": ApiAgent}
ALL_AGENTS = ["recon", "web_vuln", "authz", "api", "exploit", "analysis", "reporting"]


def _node(agent_cls, ctx: ScanContext) -> Callable:
    agent = agent_cls()

    async def run(state: ScanState) -> dict:
        return await agent.execute(ctx, state)

    return run


async def _authorize_node(ctx: ScanContext, state: ScanState) -> dict:
    ctx.killswitch.check()
    await ctx.event("status", f"authorized scan of {ctx.scope.describe()}", agent="orchestrator")
    return {"status": ScanStatus.RUNNING.value}


def build_graph(ctx: ScanContext, selected: list[str]):
    """Build and compile the LangGraph. Raises ImportError if unavailable."""
    from langgraph.graph import END, START, StateGraph

    async def authorize(state: ScanState) -> dict:
        return await _authorize_node(ctx, state)

    builder = StateGraph(ScanState)
    builder.add_node("authorize", authorize)
    builder.add_node("recon", _node(ReconAgent, ctx))
    for name, cls in ASSESSMENT.items():
        builder.add_node(name, _node(cls, ctx))
    builder.add_node("validate", _node(ExploitValidationAgent, ctx))
    builder.add_node("analysis", _node(AnalysisAgent, ctx))
    builder.add_node("reporting", _node(ReportingAgent, ctx))

    builder.add_edge(START, "authorize")
    builder.add_edge("authorize", "recon")

    active = [a for a in ASSESSMENT if a in selected] or ["web_vuln"]

    def fan_out(state: ScanState) -> list[str]:
        return active

    builder.add_conditional_edges("recon", fan_out, active)
    for name in active:
        builder.add_edge(name, "validate")
    builder.add_edge("validate", "analysis")
    builder.add_edge("analysis", "reporting")
    builder.add_edge("reporting", END)
    return builder.compile()


async def _run_native(ctx: ScanContext, state: ScanState, selected: list[str]) -> ScanState:
    """Fallback runner with the same topology, using asyncio.gather for fan-out."""
    from .state import _merge_status

    def merge(update: dict):
        for k, v in update.items():
            if k in ("tech", "endpoints", "candidates", "validated", "findings", "leads"):
                state[k] = state.get(k, []) + v
            elif k == "agent_status":
                state[k] = _merge_status(state.get(k, {}), v)
            else:
                state[k] = v

    merge(await _authorize_node(ctx, state))
    merge(await ReconAgent().execute(ctx, state))

    active = [a for a in ASSESSMENT if a in selected] or ["web_vuln"]
    results = await asyncio.gather(*[ASSESSMENT[a]().execute(ctx, state) for a in active])
    for r in results:
        merge(r)

    merge(await ExploitValidationAgent().execute(ctx, state))
    merge(await AnalysisAgent().execute(ctx, state))
    merge(await ReportingAgent().execute(ctx, state))
    state["status"] = ScanStatus.COMPLETED.value
    return state


async def run_scan(ctx: ScanContext, selected: list[str], *, use_langgraph: bool = True) -> ScanState:
    """Execute a full scan. Prefers LangGraph; falls back to the native runner."""
    initial: ScanState = {
        "scan_id": ctx.scan_id,
        "authorization_id": ctx.authorization_id,
        "target_url": ctx.target_url,
        "profile": ctx.profile,
        "selected_agents": selected,
        "tech": [], "endpoints": [], "candidates": [], "validated": [],
        "findings": [], "leads": [], "agent_status": {},
        "status": ScanStatus.RUNNING.value, "report_paths": {}, "error": None,
    }
    if use_langgraph:
        try:
            graph = build_graph(ctx, selected)
            final = await graph.ainvoke(initial, {"recursion_limit": 50})
            final["status"] = ScanStatus.COMPLETED.value
            return final
        except ImportError:
            await ctx.event("log", "LangGraph unavailable; using native runner", agent="orchestrator")
        except Exception as e:
            await ctx.event("error", f"graph error, falling back to native runner: {e}",
                            agent="orchestrator")
    return await _run_native(ctx, initial, selected)
