"""Authorization — prove the operator controls the target before scanning.

A scan cannot run against a target until an :class:`Authorization` exists for
it. Authorization is obtained by proving control of the host via **one** of:

* **DNS TXT**   ``aegis-site-verification=<token>`` on the host (needs dnspython)
* **well-known file**  ``GET /.well-known/aegis-authorization.txt`` → ``<token>``
* **HTTP header**  ``X-Aegis-Authorization: <token>`` on the homepage

Verification fetches are themselves SSRF-guarded (you can't use verification to
probe internal hosts) but are exempt from the "must already be authorized"
check — they are *how you become* authorized. On success a signed record is
produced; the HMAC signature lets the API trust a record without re-verifying.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, Field

from .scope import ScopeSpec
from .ssrf import SSRFGuard

Method = Literal["dns", "file", "header"]


def make_token(target: str, secret: str) -> str:
    """Deterministic per-target token so re-issuing is idempotent, but still
    unguessable without the server secret."""
    mac = hmac.new(secret.encode(), f"verify:{target}".encode(), hashlib.sha256)
    return "aegis-" + mac.hexdigest()[:32]


class Authorization(BaseModel):
    id: str = Field(default_factory=lambda: "authz_" + secrets.token_hex(8))
    target_url: str
    host: str
    scope: dict                              # ScopeSpec.to_dict()
    method: Method
    operator: str = "unknown"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: datetime
    signature: str = ""

    def scope_spec(self) -> ScopeSpec:
        return ScopeSpec.from_dict(self.scope)

    def is_valid(self) -> bool:
        return datetime.now(timezone.utc) < self.expires_at

    def _signing_payload(self) -> bytes:
        return "|".join([
            self.id, self.target_url, self.host, self.method,
            self.operator, self.created_at.isoformat(), self.expires_at.isoformat(),
        ]).encode()

    def sign(self, secret: str) -> "Authorization":
        self.signature = hmac.new(secret.encode(), self._signing_payload(), hashlib.sha256).hexdigest()
        return self

    def verify_signature(self, secret: str) -> bool:
        expected = hmac.new(secret.encode(), self._signing_payload(), hashlib.sha256).hexdigest()
        return hmac.compare_digest(expected, self.signature)


class VerificationError(Exception):
    pass


class AuthorizationService:
    def __init__(self, secret: str, ttl_hours: int = 72):
        self._secret = secret
        self._ttl = timedelta(hours=ttl_hours)

    def issue(self, target_url: str) -> str:
        return make_token(target_url, self._secret)

    def instructions(self, target_url: str) -> dict:
        token = self.issue(target_url)
        return {
            "token": token,
            "methods": {
                "dns": f"Add a DNS TXT record: aegis-site-verification={token}",
                "file": f"Serve {token} at /.well-known/aegis-authorization.txt",
                "header": f"Return header  X-Aegis-Authorization: {token}  on the homepage",
            },
        }

    async def verify(
        self,
        target_url: str,
        method: Method,
        *,
        http_client_factory,
        operator: str = "unknown",
        include_subdomains: bool = True,
    ) -> Authorization:
        """Run the chosen proof. ``http_client_factory(scope, ssrf)`` returns a
        GuardedHttpClient bound to a verification-only scope."""
        token = self.issue(target_url)
        scope = ScopeSpec.from_target(target_url, include_subdomains=include_subdomains)
        host = scope.check(target_url)

        ok = False
        if method == "dns":
            ok = self._verify_dns(host, token)
        elif method in ("file", "header"):
            ok = await self._verify_http(target_url, token, method, scope, http_client_factory)
        else:
            raise VerificationError(f"unknown method {method!r}")

        if not ok:
            raise VerificationError(
                f"{method} verification failed for {host}: token not found"
            )

        authz = Authorization(
            target_url=target_url,
            host=host,
            scope=scope.to_dict(),
            method=method,
            operator=operator,
            expires_at=datetime.now(timezone.utc) + self._ttl,
        ).sign(self._secret)
        return authz

    # --- individual proof methods ---
    def _verify_dns(self, host: str, token: str) -> bool:
        try:
            import dns.resolver  # type: ignore
        except ImportError as e:
            raise VerificationError(
                "DNS verification needs dnspython (pip install dnspython); "
                "use the file or header method instead"
            ) from e
        try:
            answers = dns.resolver.resolve(host, "TXT")
        except Exception as e:  # NXDOMAIN, timeout, etc.
            raise VerificationError(f"DNS TXT lookup failed for {host}: {e}") from e
        needle = f"aegis-site-verification={token}"
        for rdata in answers:
            txt = b"".join(getattr(rdata, "strings", [])).decode(errors="replace")
            if needle in txt or needle in str(rdata).strip('"'):
                return True
        return False

    async def _verify_http(self, target_url, token, method, scope, http_client_factory) -> bool:
        ssrf = SSRFGuard(scope)
        client = http_client_factory(scope, ssrf)
        try:
            if method == "file":
                base = target_url.rstrip("/")
                url = base + "/.well-known/aegis-authorization.txt"
                ex = await client.get(url)
                return ex.status == 200 and token in ex.text
            else:  # header
                ex = await client.get(target_url if "://" in target_url else "https://" + target_url)
                hv = {k.lower(): v for k, v in ex.response_headers.items()}
                return hv.get("x-aegis-authorization", "").strip() == token
        finally:
            await client.aclose()
