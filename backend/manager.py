"""ScanManager — lifecycle, control, event streaming, persistence.

Owns running scans: builds the safety core per scan, wires an event sink that
both persists and fan-outs to WebSocket subscribers, runs the orchestrator in a
background task, and exposes pause/resume/stop. Authorization is required before
a scan can be created.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

from .config import get_settings
from .db import session_scope
from .domain import Event, Finding, ScanStatus
from .models import AuthorizationRecord, EventRecord, FindingRecord, ScanRecord
from .orchestrator.graph import run_scan
from .orchestrator.state import ScanContext
from .safety import AuditLog, Budget, KillSwitch, RateLimiter, ScopeSpec, SSRFGuard
from .safety.authorization import Authorization, AuthorizationService, VerificationError
from .tools.http_client import GuardedHttpClient
from .tools.llm import LLMClient


class ScanManager:
    def __init__(self):
        self.settings = get_settings()
        self.authz_service = AuthorizationService(
            self.settings.signing_secret, self.settings.authorization_ttl_hours
        )
        self._contexts: dict[str, ScanContext] = {}
        self._tasks: dict[str, asyncio.Task] = {}
        self._subscribers: dict[str, set[asyncio.Queue]] = {}

    # ---------------- authorization ----------------
    def authorization_instructions(self, target_url: str) -> dict:
        return self.authz_service.instructions(target_url)

    async def verify_authorization(self, target_url: str, method: str, operator: str,
                                   include_subdomains: bool = True) -> Authorization:
        def factory(scope, ssrf):
            return GuardedHttpClient(
                scope=scope, ssrf=ssrf,
                rate_limiter=RateLimiter(per_host_rps=self.settings.default_per_host_rps),
                budget=Budget(max_requests=20),
                audit=AuditLog(self.settings.data_dir / "verify-audit.jsonl"),
                killswitch=KillSwitch(), scan_id="verify",
            )
        authz = await self.authz_service.verify(
            target_url, method, http_client_factory=factory, operator=operator,
            include_subdomains=include_subdomains,
        )
        async with session_scope() as s:
            s.add(AuthorizationRecord(
                id=authz.id, target_url=authz.target_url, host=authz.host, method=authz.method,
                operator=authz.operator, scope=authz.scope,
                created_at=authz.created_at, expires_at=authz.expires_at, signature=authz.signature,
            ))
        return authz

    async def get_authorization(self, authorization_id: str) -> Authorization | None:
        from sqlmodel import select
        async with session_scope() as s:
            rec = (await s.exec(select(AuthorizationRecord).where(
                AuthorizationRecord.id == authorization_id))).first()
        if not rec:
            return None
        # SQLite returns naive datetimes; reattach UTC so the signed isoformat
        # matches what was signed at creation time.
        from datetime import timezone as _tz

        def _utc(dt):
            return dt.replace(tzinfo=_tz.utc) if dt.tzinfo is None else dt

        authz = Authorization(
            id=rec.id, target_url=rec.target_url, host=rec.host, scope=rec.scope,
            method=rec.method, operator=rec.operator, created_at=_utc(rec.created_at),
            expires_at=_utc(rec.expires_at), signature=rec.signature,
        )
        return authz

    # ---------------- scan lifecycle ----------------
    async def create_scan(self, authorization_id: str, profile: str, agents: list[str]) -> ScanRecord:
        authz = await self.get_authorization(authorization_id)
        if not authz:
            raise VerificationError("unknown authorization id")
        if not authz.verify_signature(self.settings.signing_secret):
            raise VerificationError("authorization signature invalid")
        if not authz.is_valid():
            raise VerificationError("authorization has expired — re-verify the target")

        import secrets
        scan = ScanRecord(
            id="scan_" + secrets.token_hex(6), authorization_id=authz.id,
            target_url=authz.target_url, profile=profile,
            selected_agents=agents or ["web_vuln", "authz", "api"],
            status=ScanStatus.CREATED.value,
        )
        async with session_scope() as s:
            s.add(scan)
        return scan

    def _build_context(self, scan: ScanRecord, authz: Authorization) -> ScanContext:
        scope = ScopeSpec.from_dict(authz.scope)
        audit = AuditLog(self.settings.data_dir / f"audit-{scan.id}.jsonl")

        async def emit(ev: Event):
            await self._persist_event(ev)
            await self._broadcast(scan.id, ev)

        ctx = ScanContext(
            scan_id=scan.id, authorization_id=authz.id, target_url=authz.target_url,
            profile=scan.profile, scope=scope, settings=self.settings, audit=audit,
            budget=Budget(self.settings.default_request_budget, self.settings.default_time_budget_s),
            rate_limiter=RateLimiter(per_host_rps=self.settings.default_per_host_rps,
                                     max_concurrency=self.settings.default_max_concurrency),
            killswitch=KillSwitch(), llm=LLMClient(), emit=emit,
        )
        return ctx

    async def start_scan(self, scan_id: str) -> None:
        from sqlmodel import select
        async with session_scope() as s:
            scan = (await s.exec(select(ScanRecord).where(ScanRecord.id == scan_id))).first()
        if not scan:
            raise VerificationError("unknown scan id")
        authz = await self.get_authorization(scan.authorization_id)
        if not authz or not authz.is_valid():
            raise VerificationError("authorization missing or expired")

        ctx = self._build_context(scan, authz)
        self._contexts[scan_id] = ctx
        self._tasks[scan_id] = asyncio.create_task(self._run(scan, ctx))

    async def _run(self, scan: ScanRecord, ctx: ScanContext) -> None:
        await self._update_scan(scan.id, status=ScanStatus.RUNNING.value,
                                started_at=datetime.now(timezone.utc))
        try:
            state = await run_scan(ctx, scan.selected_agents, use_langgraph=True)
            await self._persist_findings(scan.id, state.get("findings", []))
            status = (ScanStatus.STOPPED.value if ctx.killswitch.engaged
                      else ScanStatus.COMPLETED.value)
            await self._update_scan(
                scan.id, status=status, finished_at=datetime.now(timezone.utc),
                stats={"agent_status": state.get("agent_status", {}),
                       "report_paths": state.get("report_paths", {}),
                       "counts": self._counts(state.get("findings", [])),
                       "requests": ctx.budget.used,
                       "kill_reason": ctx.killswitch.reason},
            )
            await ctx.event("status", f"scan {status}", agent="orchestrator")
        except Exception as e:
            await self._update_scan(scan.id, status=ScanStatus.FAILED.value,
                                    finished_at=datetime.now(timezone.utc), error=str(e)[:500])
            await ctx.event("error", f"scan failed: {e}", agent="orchestrator")
        finally:
            await self._broadcast(scan.id, Event(scan_id=scan.id, type="scan_end",
                                                 message="stream closed"))

    def pause_scan(self, scan_id: str) -> bool:
        ctx = self._contexts.get(scan_id)
        if ctx:
            ctx.pause()
            return True
        return False

    def resume_scan(self, scan_id: str) -> bool:
        ctx = self._contexts.get(scan_id)
        if ctx:
            ctx.resume()
            return True
        return False

    def stop_scan(self, scan_id: str) -> bool:
        ctx = self._contexts.get(scan_id)
        if ctx:
            ctx.killswitch.engage("operator stop")
            ctx.resume()  # unblock if paused so it can observe the kill
            return True
        return False

    # ---------------- events / subscribers ----------------
    def subscribe(self, scan_id: str) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=1000)
        self._subscribers.setdefault(scan_id, set()).add(q)
        return q

    def unsubscribe(self, scan_id: str, q: asyncio.Queue) -> None:
        self._subscribers.get(scan_id, set()).discard(q)

    async def _broadcast(self, scan_id: str, ev: Event) -> None:
        for q in list(self._subscribers.get(scan_id, set())):
            try:
                q.put_nowait(ev)
            except asyncio.QueueFull:
                pass

    # ---------------- persistence helpers ----------------
    async def _persist_event(self, ev: Event) -> None:
        async with session_scope() as s:
            s.add(EventRecord(id=ev.id, scan_id=ev.scan_id, ts=ev.ts, agent=ev.agent,
                              type=ev.type, message=ev.message, data=ev.data))

    async def _persist_findings(self, scan_id: str, findings: list[dict]) -> None:
        async with session_scope() as s:
            for fd in findings:
                f = Finding(**fd)
                s.add(FindingRecord(
                    id=f.id, scan_id=scan_id, agent=f.agent, title=f.title,
                    severity=f.severity.value, category=f.category, status=f.status.value,
                    cvss_score=f.cvss_score, dedup_key=f.dedup_key, data=f.model_dump(mode="json"),
                ))

    async def _update_scan(self, scan_id: str, **fields) -> None:
        from sqlmodel import select
        async with session_scope() as s:
            scan = (await s.exec(select(ScanRecord).where(ScanRecord.id == scan_id))).first()
            if scan:
                for k, v in fields.items():
                    setattr(scan, k, v)
                s.add(scan)

    @staticmethod
    def _counts(findings: list[dict]) -> dict:
        c = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            c[f.get("severity", "info")] = c.get(f.get("severity", "info"), 0) + 1
        return c

    async def list_scans(self) -> list[ScanRecord]:
        from sqlmodel import select
        async with session_scope() as s:
            return list((await s.exec(select(ScanRecord).order_by(ScanRecord.created_at.desc()))).all())

    async def get_scan(self, scan_id: str) -> ScanRecord | None:
        from sqlmodel import select
        async with session_scope() as s:
            return (await s.exec(select(ScanRecord).where(ScanRecord.id == scan_id))).first()

    async def get_findings(self, scan_id: str) -> list[FindingRecord]:
        from sqlmodel import select
        async with session_scope() as s:
            return list((await s.exec(select(FindingRecord).where(
                FindingRecord.scan_id == scan_id))).all())


manager = ScanManager()
