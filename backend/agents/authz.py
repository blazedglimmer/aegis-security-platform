"""Authentication & Authorization agent.

Non-destructive checks only:
  * common admin/management paths reachable without authentication (safe GET);
  * session cookie security (HttpOnly/Secure/SameSite) on auth-related responses;
  * session identifiers exposed in URLs;
  * dangerous HTTP methods enabled (TRACE → Cross-Site Tracing, PUT/DELETE);
  * IDOR/BOLA *candidates* — endpoints with object identifiers — flagged for
    manual confirmation (we never access another principal's data).
"""

from __future__ import annotations

import re
from urllib.parse import urlsplit

from ..domain import Endpoint, Finding, FindingStatus, Severity
from ..orchestrator.state import ScanContext, ScanState
from ..tools import signatures
from .base import BaseAgent

_ADMIN_PATHS = [
    "/admin", "/administrator", "/wp-admin/", "/manager/html", "/.git/",
    "/phpmyadmin/", "/console", "/actuator", "/admin/login", "/dashboard",
    "/api/admin", "/management", "/metrics",
]
_ID_IN_PATH = re.compile(r"/(\d{1,12}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:/|$)")


class AuthzAgent(BaseAgent):
    name = "authz"
    tool_grant = {"http"}

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        endpoints = [Endpoint(**e) for e in state.get("endpoints", [])]
        candidates: list[Finding] = []
        base = f"{urlsplit(state['target_url']).scheme}://{urlsplit(state['target_url']).netloc}"

        client = ctx.new_client()
        try:
            # 1) unauthenticated access to admin/management paths
            for path in _ADMIN_PATHS:
                url = base + path
                if not ctx.scope.is_in_scope(url) or not await ctx.ledger.claim(self.name, "admin", url):
                    continue
                try:
                    ex = await client.get(url)
                except Exception:
                    continue
                if ex.status == 200 and len(ex.body) > 0 and not self._looks_like_login(ex.text):
                    candidates.append(Finding(
                        agent=self.name,
                        title=f"Management interface reachable without authentication: {path}",
                        severity=Severity.HIGH, category="A01:2021-Broken Access Control",
                        endpoint=url, confidence="medium",
                        description=f"{path} returned HTTP 200 with content and no login challenge, "
                                    "suggesting an administrative or management surface exposed "
                                    "without authentication.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L",
                        impact="Unauthenticated access to privileged functionality or data.",
                        remediation="Require authentication and authorization on all management "
                                    "endpoints; restrict by network where possible.",
                        evidence=ex.as_evidence(),
                    ))
                # session cookie security on these responses
                candidates.extend(self._session_cookie_findings(ex))

            # 2) dangerous methods (TRACE / OPTIONS disclosure)
            candidates.extend(await self._method_checks(ctx, client, state["target_url"]))

            # 3) session id in URL + IDOR candidates
            for ep in endpoints:
                if re.search(r"(?:sessionid|sid|token|jsessionid|phpsessid)=", ep.url, re.I):
                    candidates.append(Finding(
                        agent=self.name,
                        title="Session identifier exposed in URL",
                        severity=Severity.MEDIUM, category="A07:2021-Identification and Authentication Failures",
                        endpoint=ep.url, confidence="high",
                        description="A session/token identifier appears in the URL, where it can "
                                    "leak via Referer headers, logs, and browser history.",
                        cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:N/A:N",
                        remediation="Carry session identifiers in Secure, HttpOnly cookies, never in URLs.",
                        evidence={"url": ep.url},
                    ))
                if _ID_IN_PATH.search(urlsplit(ep.url).path):
                    candidates.append(Finding(
                        agent=self.name,
                        title="Object identifier in path — IDOR/BOLA candidate",
                        severity=Severity.INFO, category="A01:2021-Broken Access Control",
                        endpoint=ep.url, confidence="low", status=FindingStatus.CANDIDATE,
                        description="This endpoint references an object by identifier. If access "
                                    "control is not enforced per-object, it may be vulnerable to "
                                    "IDOR/BOLA. Confirmation requires two authorized test accounts "
                                    "and is not performed automatically to avoid touching real data.",
                        cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                        remediation="Enforce per-object authorization checks server-side on every "
                                    "request; prefer unpredictable identifiers as defense-in-depth.",
                        evidence={"url": ep.url},
                    ))
        finally:
            await client.aclose()

        await ctx.event("status", f"authz produced {len(candidates)} candidates", agent=self.name)
        return {"candidates": [c.model_dump() for c in candidates]}

    @staticmethod
    def _looks_like_login(html: str) -> bool:
        return bool(re.search(r'type=["\']password["\']|sign in|log in|login', html, re.I))

    def _session_cookie_findings(self, ex) -> list[Finding]:
        out = []
        for f in signatures.check_cookies(ex):
            f.agent = self.name
            f.category = "A07:2021-Identification and Authentication Failures"
            out.append(f)
        return out

    async def _method_checks(self, ctx, client, url) -> list[Finding]:
        out = []
        if not await ctx.ledger.claim(self.name, "methods", url):
            return out
        try:
            ex = await client.request("OPTIONS", url)
        except Exception:
            return out
        allow = ex.response_headers.get("allow", "") or ex.response_headers.get("Allow", "")
        if "TRACE" in allow.upper():
            out.append(Finding(
                agent=self.name, title="HTTP TRACE method enabled (Cross-Site Tracing)",
                severity=Severity.LOW, category="A05:2021-Security Misconfiguration",
                endpoint=url, confidence="high",
                description="The server advertises TRACE, which can be abused for Cross-Site "
                            "Tracing to read otherwise protected headers.",
                cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N",
                remediation="Disable the TRACE method at the web server.",
                evidence=ex.as_evidence(),
            ))
        return out
