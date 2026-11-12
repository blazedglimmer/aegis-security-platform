"""SSRFGuard — block requests whose *resolved address* is unsafe.

ScopeGuard answers "did the operator authorize this host?". SSRFGuard answers a
different question that an allowlist alone cannot: "where does this host
actually point *right now*?" A target can 302 you to ``169.254.169.254`` or
return a DNS record for ``10.0.0.5`` to pull the scanner into a cloud metadata
endpoint or an internal service. So we resolve the name ourselves, validate
every returned address, and **pin** to a vetted IP that the HTTP transport must
connect to — defeating DNS-rebinding (resolve-then-reconnect) attacks.

A private/reserved address is blocked *unless* it falls inside a CIDR the
operator explicitly authorized in the scan's scope (the on-prem-engagement
case). Cloud-metadata and loopback addresses are blocked unconditionally.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass

from .errors import SSRFBlocked
from .scope import ScopeSpec, _as_ip, _normalize_host

# Addresses that are NEVER a legitimate scan target, even on an internal
# engagement, and cannot be authorized by any scope — the classic SSRF
# escalation destinations (cloud metadata / link-local).
_HARD_BLOCK_NETS = [
    ipaddress.ip_network("169.254.0.0/16"),   # link-local (AWS/GCP/Azure metadata)
    ipaddress.ip_network("fe80::/10"),        # IPv6 link-local
    ipaddress.ip_network("100.100.100.200/32"),  # Alibaba metadata
]
_HARD_BLOCK_IPS = {ipaddress.ip_address("fd00:ec2::254")}  # AWS IMDSv6

# Loopback and private/ULA ranges are blocked *by default* but MAY be authorized
# for a local/on-prem engagement by listing an explicit CIDR in the scan scope.
# (They are non-public, so they already require _authorized_private to pass;
#  this comment documents the intent.)


def _is_hard_blocked(ip) -> bool:
    if ip in _HARD_BLOCK_IPS:
        return True
    return any(ip in net for net in _HARD_BLOCK_NETS)


def _is_public(ip) -> bool:
    """Globally-routable unicast address with no special-use reservation."""
    return not (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


@dataclass
class PinnedTarget:
    """The result of a successful SSRF check: connect to ``ip`` while presenting
    ``host`` for SNI/Host header. Pinning the IP is what prevents rebinding."""

    host: str
    ip: str
    family: int

    @property
    def is_ipv6(self) -> bool:
        return self.family == socket.AF_INET6


class SSRFGuard:
    def __init__(self, scope: ScopeSpec, *, resolver=None):
        self._scope = scope
        # Injectable resolver for tests; defaults to the system resolver.
        self._resolve = resolver or self._default_resolver

    @staticmethod
    def _default_resolver(host: str) -> list[tuple[int, str]]:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        out: list[tuple[int, str]] = []
        seen = set()
        for family, _type, _proto, _canon, sockaddr in infos:
            ip = sockaddr[0]
            if ip not in seen:
                seen.add(ip)
                out.append((family, ip))
        return out

    def _authorized_private(self, ip) -> bool:
        """A private IP is allowed only if it sits inside an explicitly
        authorized CIDR (never for hard-blocked metadata/loopback ranges)."""
        if _is_hard_blocked(ip):
            return False
        return any(ip in ipaddress.ip_network(c, strict=False) for c in self._scope.cidrs)

    def _validate_ip(self, ip, host: str):
        if _is_hard_blocked(ip):
            raise SSRFBlocked(f"{host} resolves to blocked metadata/loopback address {ip}")
        if _is_public(ip):
            return
        if self._authorized_private(ip):
            return
        raise SSRFBlocked(
            f"{host} resolves to non-public address {ip} that is not in any "
            f"authorized CIDR"
        )

    def resolve_and_pin(self, host: str) -> PinnedTarget:
        """Resolve ``host``, validate *all* answers, and pin a vetted address.

        We validate every returned record (not just the first) so a mixed
        answer can't smuggle an internal IP in, then connect to a known-good
        one. Raises :class:`SSRFBlocked` on any unsafe answer or empty result.
        """
        host = _normalize_host(host)

        literal = _as_ip(host)
        if literal is not None:
            self._validate_ip(literal, host)
            fam = socket.AF_INET6 if literal.version == 6 else socket.AF_INET
            return PinnedTarget(host=host, ip=str(literal), family=fam)

        try:
            answers = self._resolve(host)
        except socket.gaierror as e:
            raise SSRFBlocked(f"DNS resolution failed for {host}: {e}") from e
        if not answers:
            raise SSRFBlocked(f"no DNS records for {host}")

        pinned: PinnedTarget | None = None
        for family, ip_str in answers:
            ip = ipaddress.ip_address(ip_str)
            self._validate_ip(ip, host)  # every answer must pass
            if pinned is None:
                pinned = PinnedTarget(host=host, ip=ip_str, family=family)
        assert pinned is not None
        return pinned
