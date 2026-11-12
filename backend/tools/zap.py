"""OWASP ZAP wrapper via the ZAP daemon API — optional.

Active only when ``AEGIS_ZAP_API_URL`` points at a running ZAP daemon (typically
``http://127.0.0.1:8080``). We drive ZAP's spider + passive scan and, on the
``safe``/``aggressive`` profiles, its active scanner restricted to the target,
then pull structured alerts and map them to Aegis findings.

The ZAP daemon is a local control plane; requests here go to that daemon, not to
the target. ZAP's own traffic to the target should be constrained by a ZAP
context/scope and, in production, a network-restricted sandbox.
"""

from __future__ import annotations

import asyncio

import httpx

from ..domain import Finding, Severity
from ..safety.scope import ScopeSpec

_RISK = {"0": Severity.INFO, "1": Severity.LOW, "2": Severity.MEDIUM, "3": Severity.HIGH,
         "Informational": Severity.INFO, "Low": Severity.LOW, "Medium": Severity.MEDIUM,
         "High": Severity.HIGH}


class ZapScanner:
    def __init__(self, scope: ScopeSpec, *, api_url: str | None, api_key: str | None = None,
                 profile: str = "safe"):
        self.scope = scope
        self.api_url = api_url.rstrip("/") if api_url else None
        self.api_key = api_key or ""
        self.profile = profile

    @property
    def available(self) -> bool:
        return bool(self.api_url)

    async def _probe(self, client: httpx.AsyncClient) -> bool:
        try:
            r = await client.get(f"{self.api_url}/JSON/core/view/version/",
                                 params={"apikey": self.api_key}, timeout=5)
            return r.status_code == 200
        except httpx.HTTPError:
            return False

    async def scan(self, target_url: str, *, active: bool | None = None,
                   max_wait: float = 900.0) -> list[Finding]:
        if not self.available or not self.scope.is_in_scope(target_url):
            return []
        if active is None:
            active = self.profile in ("safe", "aggressive")

        async with httpx.AsyncClient() as client:
            if not await self._probe(client):
                return []
            try:
                await self._spider(client, target_url, max_wait)
                await self._wait_passive(client, max_wait)
                if active:
                    await self._active(client, target_url, max_wait)
                return await self._alerts(client, target_url)
            except httpx.HTTPError:
                return await self._alerts(client, target_url)

    async def _call(self, client, path, **params):
        params["apikey"] = self.api_key
        r = await client.get(f"{self.api_url}{path}", params=params, timeout=30)
        r.raise_for_status()
        return r.json()

    async def _spider(self, client, url, max_wait):
        res = await self._call(client, "/JSON/spider/action/scan/", url=url, recurse="true")
        sid = res.get("scan")
        await self._poll(client, "/JSON/spider/view/status/", {"scanId": sid}, "status", max_wait)

    async def _wait_passive(self, client, max_wait):
        async def records():
            r = await self._call(client, "/JSON/pscan/view/recordsToScan/")
            return 0 if int(r.get("recordsToScan", 0)) == 0 else 1
        await self._poll_fn(records, max_wait)

    async def _active(self, client, url, max_wait):
        res = await self._call(client, "/JSON/ascan/action/scan/", url=url, recurse="true",
                               inScopeOnly="true")
        sid = res.get("scan")
        if sid and sid != "-1":
            await self._poll(client, "/JSON/ascan/view/status/", {"scanId": sid}, "status", max_wait)

    async def _poll(self, client, path, params, key, max_wait):
        waited = 0.0
        while waited < max_wait:
            r = await self._call(client, path, **params)
            if int(r.get(key, 0)) >= 100:
                return
            await asyncio.sleep(2)
            waited += 2

    async def _poll_fn(self, fn, max_wait):
        waited = 0.0
        while waited < max_wait:
            if await fn() == 0:
                return
            await asyncio.sleep(2)
            waited += 2

    async def _alerts(self, client, base_url) -> list[Finding]:
        data = await self._call(client, "/JSON/core/view/alerts/", baseurl=base_url, count="1000")
        out: list[Finding] = []
        seen = set()
        for a in data.get("alerts", []):
            url = a.get("url", "")
            if url and not self.scope.is_in_scope(url):
                continue
            key = (a.get("alertRef") or a.get("pluginId"), url)
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(
                agent="web_vuln",
                title=a.get("alert", "ZAP alert"),
                severity=_RISK.get(str(a.get("risk")), Severity.INFO),
                category=self._category(a),
                endpoint=url,
                description=a.get("description", ""),
                remediation=a.get("solution", ""),
                references=[r for r in (a.get("reference", "") or "").split("\n") if r],
                confidence={"High": "high", "Medium": "medium", "Low": "low"}.get(a.get("confidence"), "medium"),
                evidence={
                    "tool": "zap", "param": a.get("param"), "attack": a.get("attack"),
                    "evidence": a.get("evidence"), "cweid": a.get("cweid"),
                    "plugin_id": a.get("pluginId"),
                },
            ))
        return out

    @staticmethod
    def _category(a: dict) -> str:
        cwe = str(a.get("cweid", ""))
        mapping = {
            "79": "A03:2021-Injection", "89": "A03:2021-Injection",
            "352": "A01:2021-Broken Access Control", "918": "A10:2021-Server-Side Request Forgery",
            "200": "A05:2021-Security Misconfiguration", "16": "A05:2021-Security Misconfiguration",
            "287": "A07:2021-Identification and Authentication Failures",
        }
        return mapping.get(cwe, "misc")
