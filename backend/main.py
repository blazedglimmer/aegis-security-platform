"""Aegis FastAPI application: REST + WebSocket + dashboard.

Endpoints
  POST /api/authorizations                 → verification token + instructions
  POST /api/authorizations/verify          → run proof, persist signed authorization
  POST /api/scans                          → create a scan (requires authorization)
  POST /api/scans/{id}/start|pause|resume|stop
  GET  /api/scans                          → list
  GET  /api/scans/{id}                     → status + stats
  GET  /api/scans/{id}/findings            → findings
  GET  /api/scans/{id}/report.(json|md|html)
  WS   /api/scans/{id}/events              → live event stream
  GET  /                                   → dashboard
"""

from __future__ import annotations

import asyncio
import contextlib
from pathlib import Path

from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from .config import get_settings
from .db import init_db
from .manager import manager
from .safety.authorization import VerificationError
from .safety.errors import ScopeViolation, SSRFBlocked
from .schemas import AuthorizeRequest, CreateScanRequest, VerifyRequest

settings = get_settings()
app = FastAPI(title="Aegis", version="0.1.0",
              description="Authorized multi-agent web security assessment platform")

FRONTEND = Path(__file__).resolve().parent.parent / "frontend"


@app.on_event("startup")
async def _startup():
    await init_db()


@app.get("/api/health")
async def health():
    from .tools.llm import LLMClient
    from .tools.nuclei import NucleiScanner
    from .safety import ScopeSpec
    nuclei = NucleiScanner(ScopeSpec(), binary=settings.nuclei_path)
    return {
        "status": "ok",
        "llm_available": LLMClient().available,
        "nuclei_available": nuclei.available,
        "zap_configured": bool(settings.zap_api_url),
    }


# ---------------- authorization ----------------
@app.post("/api/authorizations")
async def create_authorization(req: AuthorizeRequest):
    try:
        return manager.authorization_instructions(req.target_url)
    except ScopeViolation as e:
        raise HTTPException(400, f"invalid target: {e}")


@app.post("/api/authorizations/verify")
async def verify_authorization(req: VerifyRequest):
    try:
        authz = await manager.verify_authorization(
            req.target_url, req.method, req.operator, req.include_subdomains)
        return {"authorization_id": authz.id, "host": authz.host, "method": authz.method,
                "scope": authz.scope_spec().describe(), "expires_at": authz.expires_at.isoformat()}
    except VerificationError as e:
        raise HTTPException(400, str(e))
    except (ScopeViolation, SSRFBlocked) as e:
        raise HTTPException(400, f"safety refusal: {e}")


# ---------------- scans ----------------
@app.post("/api/scans")
async def create_scan(req: CreateScanRequest):
    try:
        scan = await manager.create_scan(req.authorization_id, req.profile, req.agents)
        return {"scan_id": scan.id, "status": scan.status, "target": scan.target_url}
    except VerificationError as e:
        raise HTTPException(400, str(e))


@app.post("/api/scans/{scan_id}/start")
async def start_scan(scan_id: str):
    try:
        await manager.start_scan(scan_id)
        return {"scan_id": scan_id, "status": "running"}
    except VerificationError as e:
        raise HTTPException(400, str(e))


@app.post("/api/scans/{scan_id}/pause")
async def pause_scan(scan_id: str):
    return {"ok": manager.pause_scan(scan_id)}


@app.post("/api/scans/{scan_id}/resume")
async def resume_scan(scan_id: str):
    return {"ok": manager.resume_scan(scan_id)}


@app.post("/api/scans/{scan_id}/stop")
async def stop_scan(scan_id: str):
    return {"ok": manager.stop_scan(scan_id)}


@app.get("/api/scans")
async def list_scans():
    scans = await manager.list_scans()
    return [{"scan_id": s.id, "target": s.target_url, "status": s.status, "profile": s.profile,
             "created_at": s.created_at.isoformat(),
             "counts": (s.stats or {}).get("counts", {})} for s in scans]


@app.get("/api/scans/{scan_id}")
async def get_scan(scan_id: str):
    s = await manager.get_scan(scan_id)
    if not s:
        raise HTTPException(404, "unknown scan")
    return {"scan_id": s.id, "target": s.target_url, "status": s.status, "profile": s.profile,
            "selected_agents": s.selected_agents, "stats": s.stats, "error": s.error,
            "created_at": s.created_at.isoformat(),
            "started_at": s.started_at.isoformat() if s.started_at else None,
            "finished_at": s.finished_at.isoformat() if s.finished_at else None}


@app.get("/api/scans/{scan_id}/findings")
async def get_findings(scan_id: str):
    recs = await manager.get_findings(scan_id)
    return [r.data for r in recs]


@app.get("/api/scans/{scan_id}/report.{fmt}")
async def get_report(scan_id: str, fmt: str):
    if fmt not in ("json", "md", "html"):
        raise HTTPException(400, "format must be json, md, or html")
    path = settings.reports_dir / f"{scan_id}.{fmt}"
    if not path.exists():
        raise HTTPException(404, "report not generated yet")
    media = {"json": "application/json", "md": "text/markdown", "html": "text/html"}[fmt]
    return FileResponse(path, media_type=media, filename=f"aegis-{scan_id}.{fmt}")


# ---------------- live events ----------------
@app.websocket("/api/scans/{scan_id}/events")
async def scan_events(ws: WebSocket, scan_id: str):
    await ws.accept()
    q = manager.subscribe(scan_id)
    try:
        while True:
            ev = await q.get()
            await ws.send_json({
                "id": ev.id, "ts": ev.ts.isoformat(), "agent": ev.agent,
                "type": ev.type, "message": ev.message, "data": ev.data,
            })
            if ev.type == "scan_end":
                break
    except WebSocketDisconnect:
        pass
    finally:
        manager.unsubscribe(scan_id, q)
        with contextlib.suppress(Exception):
            await ws.close()


# ---------------- dashboard ----------------
@app.get("/", response_class=HTMLResponse)
async def dashboard():
    index = FRONTEND / "index.html"
    if index.exists():
        return HTMLResponse(index.read_text())
    return HTMLResponse("<h1>Aegis</h1><p>Dashboard not built.</p>")


if (FRONTEND / "src").exists():
    app.mount("/static", StaticFiles(directory=str(FRONTEND)), name="static")
