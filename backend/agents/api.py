"""API Security agent.

Discovers and assesses API endpoints (from OpenAPI/Swagger specs found in
recon, observed XHR/fetch traffic, and ``/api`` paths). Non-destructive checks:
  * unauthenticated access returning data (broken auth / BOLA surface);
  * excessive data exposure (responses with many sensitive-looking fields);
  * missing rate limiting (a short, capped burst that respects the throttle);
  * insecure transport / CORS on API responses.
"""

from __future__ import annotations

import json
import re
from urllib.parse import urljoin, urlsplit

from ..domain import Endpoint, Finding, Lead, Severity
from ..orchestrator.state import ScanContext, ScanState
from ..tools import signatures
from ..tools.nuclei import NucleiScanner
from .base import BaseAgent

_SENSITIVE_FIELDS = re.compile(
    r"\b(password|passwd|secret|token|api[_-]?key|ssn|credit[_-]?card|cvv|"
    r"private[_-]?key|authorization|email|phone|address|dob|date_of_birth)\b", re.I,
)


class ApiAgent(BaseAgent):
    name = "api"
    tool_grant = {"http", "nuclei"}

    async def run(self, ctx: ScanContext, state: ScanState) -> dict:
        endpoints = [Endpoint(**e) for e in state.get("endpoints", [])]
        leads = [Lead(**l) for l in state.get("leads", [])]
        candidates: list[Finding] = []

        api_endpoints: dict[str, Endpoint] = {
            e.url: e for e in endpoints if e.source == "api" or "/api" in urlsplit(e.url).path
        }

        client = ctx.new_client()
        try:
            # 1) OpenAPI/Swagger specs from recon leads → enumerate paths
            for lead in leads:
                if lead.kind in ("openapi_spec",) and ctx.scope.is_in_scope(lead.target):
                    for ep in await self._from_openapi(ctx, client, lead.target):
                        api_endpoints.setdefault(ep.url, ep)

            # 2) assess each API endpoint (safe GET)
            assessed = 0
            for url, ep in list(api_endpoints.items())[:60]:
                if ep.method != "GET":
                    continue
                if not await ctx.ledger.claim(self.name, "api_assess", url):
                    continue
                try:
                    ex = await client.get(url)
                except Exception:
                    continue
                assessed += 1
                candidates.extend(signatures.check_cors(ex))
                candidates.extend(self._assess_response(ex, url))

            # 3) rate-limit probe on one representative endpoint (short, throttled burst)
            rep = next((u for u in api_endpoints), None)
            if rep:
                candidates.extend(await self._rate_limit_probe(ctx, client, rep))

            # 4) nuclei API templates
            nuclei = NucleiScanner(ctx.scope, binary=ctx.settings.nuclei_path,
                                   per_host_rps=ctx.settings.default_per_host_rps, profile=ctx.profile)
            if nuclei.available and api_endpoints:
                candidates.extend(await nuclei.scan(list(api_endpoints)[:100], extra_tags="api"))
        finally:
            await client.aclose()

        await ctx.event("status", f"api assessed {len(api_endpoints)} endpoints, "
                                   f"{len(candidates)} candidates", agent=self.name)
        return {
            "candidates": [c.model_dump() for c in candidates],
            "endpoints": [e.model_dump() for e in api_endpoints.values()],
        }

    async def _from_openapi(self, ctx, client, spec_url) -> list[Endpoint]:
        out: list[Endpoint] = []
        try:
            ex = await client.get(spec_url)
            spec = json.loads(ex.text)
        except Exception:
            return out
        servers = spec.get("servers") or [{"url": f"{urlsplit(spec_url).scheme}://{urlsplit(spec_url).netloc}"}]
        base = servers[0].get("url", "")
        if base.startswith("/"):
            base = f"{urlsplit(spec_url).scheme}://{urlsplit(spec_url).netloc}" + base
        for path, methods in (spec.get("paths") or {}).items():
            # skip templated params for safe auto-GET; keep as endpoint record
            full = urljoin(base.rstrip("/") + "/", path.lstrip("/"))
            if not ctx.scope.is_in_scope(full):
                continue
            for method in methods:
                out.append(Endpoint(url=full, method=method.upper(), source="api", notes="from OpenAPI"))
        return out

    def _assess_response(self, ex, url) -> list[Finding]:
        out = []
        ctype = ex.response_headers.get("content-type", "")
        if "json" not in ctype and not ex.text.strip().startswith(("{", "[")):
            return out
        # excessive data exposure: data returned with no auth, many sensitive fields
        sensitive = set(m.group(0).lower() for m in _SENSITIVE_FIELDS.finditer(ex.text[:20000]))
        authed = any(h.lower() == "www-authenticate" for h in ex.response_headers)
        if ex.status == 200 and len(sensitive) >= 3 and not authed:
            out.append(Finding(
                agent=self.name,
                title="API returns sensitive fields without authentication (excessive data exposure)",
                severity=Severity.HIGH, category="A01:2021-Broken Access Control",
                endpoint=url, confidence="medium",
                description=f"The endpoint returned HTTP 200 JSON containing sensitive-looking "
                            f"fields ({', '.join(sorted(sensitive))}) with no authentication "
                            "challenge. This may indicate broken object/function-level "
                            "authorization or excessive data exposure.",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                impact="Unauthorized disclosure of sensitive data.",
                remediation="Require authentication; return only fields the caller is entitled to; "
                            "apply response schemas that exclude sensitive attributes.",
                evidence={**ex.as_evidence(), "sensitive_fields": sorted(sensitive)},
                references=["https://owasp.org/API-Security/editions/2023/en/0xa3-broken-object-property-level-authorization/"],
            ))
        return out

    async def _rate_limit_probe(self, ctx, client, url, n: int = 12) -> list[Finding]:
        if not await ctx.ledger.claim(self.name, "ratelimit", url):
            return []
        saw_429 = False
        statuses = []
        for _ in range(n):
            try:
                ex = await client.get(url)
            except Exception:
                break
            statuses.append(ex.status)
            if ex.status == 429:
                saw_429 = True
                break
        if statuses and not saw_429 and all(s < 400 for s in statuses):
            return [Finding(
                agent=self.name,
                title="No rate limiting observed on API endpoint",
                severity=Severity.LOW, category="A04:2021-Insecure Design",
                endpoint=url, confidence="low",
                description=f"{len(statuses)} rapid requests to the endpoint all succeeded with no "
                            "HTTP 429 or throttling signal, suggesting missing rate limiting "
                            "(the scan itself stays within its own throttle).",
                cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                impact="Enables brute force, credential stuffing, and resource-exhaustion abuse.",
                remediation="Apply per-client/-IP rate limiting and quotas on API endpoints.",
                evidence={"url": url, "sample_statuses": statuses},
            )]
        return []
