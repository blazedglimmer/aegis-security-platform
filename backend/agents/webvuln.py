"""Web Vulnerability agent — OWASP Top 10 surface over real evidence.

Three evidence sources, all optional-degrading:
  * built-in passive signature checks across sampled endpoints (always on);
  * nuclei templates (if the binary is present);
  * OWASP ZAP spider + passive/safe-active scan (if a ZAP daemon is configured).

Plus non-destructive *candidate* probes for reflected XSS (unique nonce
reflection) and SQL errors (a single-quote error oracle) on parameterized
endpoints. Candidates are handed to the Exploitation Validation agent for
safe confirmation — this agent never asserts a confirmed injection by itself.
"""

from __future__ import annotations

import re
from urllib.parse import parse_qs, urlencode, urlsplit, urlunsplit

from ..domain import Endpoint, Finding, Severity
from ..orchestrator.state import ScanContext, ScanState
from ..tools import signatures
from ..tools.nuclei import NucleiScanner
from ..tools.zap import ZapScanner
from .base import BaseAgent

_SQL_ERRORS = re.compile(
    r"SQL syntax.*MySQL|valid MySQL result|PostgreSQL.*ERROR|ORA-\d{5}|"
    r"SQLSTATE\[|Unclosed quotation mark|quoted string not properly terminated|"
    r"SQLite3::|System\.Data\.SqlClient",
    re.I,
)
_NONCE = "aeg1sX9z7q"  # unique, benign reflection marker


class WebVulnAgent(BaseAgent):
    name = "web_vuln"
    tool_grant = {"http", "nuclei", "zap"}

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        endpoints = [Endpoint(**e) for e in state.get("endpoints", [])]
        candidates: list[Finding] = []

        # 1) passive checks across a sample of endpoints
        client = ctx.new_client()
        sample = [e for e in endpoints if e.method == "GET"][:40]
        try:
            for ep in sample:
                if not await ctx.ledger.claim(self.name, "passive", ep.url):
                    continue
                try:
                    ex = await client.get(ep.url)
                except Exception:
                    continue
                candidates.extend(signatures.run_passive(ex))

            # 2) non-destructive injection candidate probes on parameterized GETs
            for ep in sample:
                params = parse_qs(urlsplit(ep.url).query)
                if not params:
                    continue
                candidates.extend(await self._probe_reflection(ctx, client, ep.url, params))
                candidates.extend(await self._probe_sql_error(ctx, client, ep.url, params))
        finally:
            await client.aclose()

        # 3) nuclei (safe tags)
        nuclei = NucleiScanner(ctx.scope, binary=ctx.settings.nuclei_path,
                               per_host_rps=ctx.settings.default_per_host_rps, profile=ctx.profile)
        if nuclei.available:
            await ctx.event("log", "running nuclei (safe templates)", agent=self.name)
            urls = [e.url for e in endpoints][:200] or [state["target_url"]]
            candidates.extend(await nuclei.scan(urls))
        else:
            await ctx.event("log", "nuclei not installed — using passive checks only", agent=self.name)

        # 4) ZAP (if configured)
        zap = ZapScanner(ctx.scope, api_url=ctx.settings.zap_api_url,
                         api_key=ctx.settings.zap_api_key, profile=ctx.profile)
        if zap.available:
            await ctx.event("log", "running OWASP ZAP scan", agent=self.name)
            candidates.extend(await zap.scan(state["target_url"]))

        await ctx.event("status", f"web_vuln produced {len(candidates)} candidates", agent=self.name)
        return {"candidates": [c.model_dump() for c in candidates]}

    def _with_param(self, url: str, params: dict, key: str, value: str) -> str:
        new = {k: v[:] for k, v in params.items()}
        new[key] = [value]
        parts = urlsplit(url)
        return urlunsplit(parts._replace(query=urlencode(new, doseq=True)))

    async def _probe_reflection(self, ctx, client, url, params) -> list[Finding]:
        out = []
        for key in list(params)[:5]:
            if not await ctx.ledger.claim(self.name, "reflection", f"{url}::{key}"):
                continue
            probe = self._with_param(url, params, key, _NONCE)
            try:
                ex = await client.get(probe)
            except Exception:
                continue
            if _NONCE in ex.text:
                ctype = ex.response_headers.get("content-type", "")
                out.append(Finding(
                    agent=self.name,
                    title=f"Reflected input in response (parameter '{key}') — possible XSS",
                    severity=Severity.MEDIUM, category="A03:2021-Injection",
                    endpoint=url, confidence="low",
                    description=f"A unique marker injected into parameter '{key}' was reflected "
                                f"unencoded in the response (content-type: {ctype}). This is a "
                                "candidate for reflected XSS and must be confirmed by the "
                                "validation agent with a context-appropriate, non-executing proof.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                    remediation="Context-encode all user input on output; apply a strict CSP.",
                    evidence={**ex.as_evidence(), "parameter": key, "marker": _NONCE},
                    references=["https://owasp.org/www-community/attacks/xss/"],
                ))
        return out

    async def _probe_sql_error(self, ctx, client, url, params) -> list[Finding]:
        out = []
        for key in list(params)[:5]:
            if not await ctx.ledger.claim(self.name, "sqlerror", f"{url}::{key}"):
                continue
            # A single quote is a read-only syntax perturbation, not a mutation.
            probe = self._with_param(url, params, key, (params[key][0] if params[key] else "") + "'")
            try:
                ex = await client.get(probe)
            except Exception:
                continue
            if _SQL_ERRORS.search(ex.text):
                out.append(Finding(
                    agent=self.name,
                    title=f"SQL error provoked by quote in parameter '{key}' — possible SQLi",
                    severity=Severity.HIGH, category="A03:2021-Injection",
                    endpoint=url, confidence="medium",
                    description=f"Appending a single quote to parameter '{key}' elicited a database "
                                "error in the response, indicating input reaches a SQL statement "
                                "unsafely. Candidate for SQL injection; confirmation uses a "
                                "non-destructive boolean oracle, never data extraction.",
                    cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
                    impact="Potential unauthorized read (and possibly write) of database contents.",
                    remediation="Use parameterized queries / prepared statements; validate input.",
                    evidence={**ex.as_evidence(), "parameter": key},
                    references=["https://owasp.org/www-community/attacks/SQL_Injection"],
                ))
        return out
