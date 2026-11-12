"""GuardedHttpClient — the one sanctioned way to make an outbound request.

Agents never see raw ``httpx``. They get one of these, already bound to a
scan's scope/guards. For every request *and every redirect hop* it runs, in
order:

    killswitch → scope → SSRF resolve+pin → rate-limit → budget → audit → send

The connection is pinned to the IP the SSRFGuard vetted (TLS SNI + cert
verification still use the real hostname), so a DNS rebind between the check and
the connect cannot redirect us to an internal address. Redirects are followed
manually so each ``Location`` is re-validated from scratch.

Every call returns an :class:`Exchange` capturing the request/response as
reproducible evidence (with secrets redacted for storage).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

import httpx

from ..safety.audit import AuditLog, _redact
from ..safety.errors import ScopeViolation
from ..safety.killswitch import KillSwitch
from ..safety.ratelimit import Budget, RateLimiter
from ..safety.scope import ScopeSpec
from ..safety.ssrf import SSRFGuard

_SAFE_MAX_BODY = 2_000_000  # cap stored bodies at 2 MB


@dataclass
class Exchange:
    """A single reproducible request/response pair — the unit of evidence."""

    method: str
    url: str
    status: int
    request_headers: dict
    response_headers: dict
    body: bytes
    elapsed_ms: float
    redirect_chain: list[str] = field(default_factory=list)
    resolved_ip: str | None = None

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")

    def as_evidence(self) -> dict:
        """Redacted, JSON-safe form for storage in findings/audit."""
        return {
            "method": self.method,
            "url": self.url,
            "status": self.status,
            "request_headers": _redact(self.request_headers),
            "response_headers": _redact(self.response_headers),
            "body_preview": self.text[:4000],
            "elapsed_ms": round(self.elapsed_ms, 1),
            "redirect_chain": self.redirect_chain,
            "resolved_ip": self.resolved_ip,
        }


class GuardedHttpClient:
    def __init__(
        self,
        *,
        scope: ScopeSpec,
        ssrf: SSRFGuard,
        rate_limiter: RateLimiter,
        budget: Budget,
        audit: AuditLog,
        killswitch: KillSwitch,
        scan_id: str = "-",
        user_agent: str = "Aegis-Scanner/0.1 (+authorized-assessment)",
        timeout: float = 20.0,
        max_redirects: int = 5,
        verify_tls: bool = True,
    ):
        self.scope = scope
        self.ssrf = ssrf
        self.rl = rate_limiter
        self.budget = budget
        self.audit = audit
        self.killswitch = killswitch
        self.scan_id = scan_id
        self.user_agent = user_agent
        self.timeout = timeout
        self.max_redirects = max_redirects
        self._client = httpx.AsyncClient(
            follow_redirects=False,       # we follow manually & re-validate each hop
            verify=verify_tls,
            timeout=timeout,
            limits=httpx.Limits(max_connections=16, max_keepalive_connections=8),
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        await self.aclose()

    def _pinned_url_and_headers(self, url: str, headers: dict) -> tuple[str, dict, str]:
        """Rewrite the URL to connect to the vetted IP while presenting the real
        host for Host header / SNI. Returns (connect_url, headers, resolved_ip)."""
        parts = urlsplit(url)
        host = self.scope.check(url)                    # scope gate (raises on fail)
        pinned = self.ssrf.resolve_and_pin(host)        # SSRF gate (raises on fail)
        port = parts.port or (443 if parts.scheme == "https" else 80)
        ip_netloc = f"[{pinned.ip}]:{port}" if pinned.is_ipv6 else f"{pinned.ip}:{port}"
        connect_url = parts._replace(netloc=ip_netloc).geturl()
        headers = dict(headers or {})
        headers.setdefault("Host", parts.netloc)
        headers.setdefault("User-Agent", self.user_agent)
        return connect_url, headers, pinned.ip

    async def request(
        self,
        method: str,
        url: str,
        *,
        headers: dict | None = None,
        params: dict | None = None,
        data=None,
        json=None,
        content=None,
    ) -> Exchange:
        self.killswitch.check()
        chain: list[str] = []
        current = url
        last_ip: str | None = None
        import time as _t

        for hop in range(self.max_redirects + 1):
            self.killswitch.check()
            host = self.scope.check(current)           # re-validate every hop
            connect_url, req_headers, resolved_ip = self._pinned_url_and_headers(current, headers or {})
            last_ip = resolved_ip

            await self.rl.acquire(host)
            try:
                self.budget.spend(1)
                self.audit.append(
                    "http_request",
                    {"method": method, "url": current, "resolved_ip": resolved_ip},
                    scan_id=self.scan_id,
                )
                started = _t.monotonic()
                try:
                    resp = await self._client.request(
                        method,
                        connect_url,
                        headers=req_headers,
                        params=params if hop == 0 else None,
                        data=data if hop == 0 else None,
                        json=json if hop == 0 else None,
                        content=content if hop == 0 else None,
                        extensions={"sni_hostname": host},
                    )
                except httpx.HTTPError as e:
                    self.killswitch.record_error()
                    self.audit.append("http_error", {"url": current, "error": str(e)}, scan_id=self.scan_id)
                    raise
                elapsed = (_t.monotonic() - started) * 1000
            finally:
                self.rl.release()

            self.killswitch.record_success()
            if resp.status_code in (429, 503):
                self.rl.penalize(host, seconds=5.0)

            chain.append(current)
            if resp.is_redirect and resp.headers.get("location"):
                nxt = urljoin(current, resp.headers["location"])
                # Re-validate the redirect target *before* following it.
                try:
                    self.scope.check(nxt)
                except ScopeViolation:
                    self.audit.append(
                        "redirect_out_of_scope",
                        {"from": current, "to": nxt},
                        scan_id=self.scan_id,
                    )
                    # Stop here; return the redirect response itself as evidence.
                    return self._to_exchange(method, current, resp, elapsed, chain, resolved_ip)
                current = nxt
                headers = headers  # carry caller headers forward (minus body)
                continue

            return self._to_exchange(method, current, resp, elapsed, chain, resolved_ip)

        # Too many redirects
        raise ScopeViolation(f"exceeded {self.max_redirects} redirects starting at {url}")

    def _to_exchange(self, method, url, resp, elapsed, chain, resolved_ip) -> Exchange:
        body = resp.content[:_SAFE_MAX_BODY]
        return Exchange(
            method=method,
            url=url,
            status=resp.status_code,
            request_headers=dict(resp.request.headers),
            response_headers=dict(resp.headers),
            body=body,
            elapsed_ms=elapsed,
            redirect_chain=chain,
            resolved_ip=resolved_ip,
        )

    async def get(self, url: str, **kw) -> Exchange:
        return await self.request("GET", url, **kw)

    async def post(self, url: str, **kw) -> Exchange:
        return await self.request("POST", url, **kw)

    async def head(self, url: str, **kw) -> Exchange:
        return await self.request("HEAD", url, **kw)
