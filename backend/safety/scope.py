"""ScopeGuard — deny-by-default authorization-scope enforcement.

A ``ScopeSpec`` is the *frozen* allowlist for one scan. ``ScopeGuard.check(url)``
is called on every request URL and on every redirect ``Location`` before the
request is released to the network. It answers one question: "is this exact
URL inside what the operator authorized?" — and refuses everything else.

Design choices that matter for safety:

* **Deny by default.** An empty scope authorizes nothing.
* **Registrable-domain matching, not substring.** ``evil-example.com`` does not
  match ``example.com``; ``example.com.attacker.net`` does not match either.
  Subdomain matching is opt-in per domain and is a true label-boundary match.
* **Ports and schemes are part of scope.** Only 80/443 + http/https by default.
* **IP scope is CIDR membership**, never string compare.
* Host comparison is case-insensitive and IDNA-normalized; a trailing dot and
  default ports are normalized away.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from urllib.parse import urlsplit

from .errors import ScopeViolation

DEFAULT_PORTS = {80, 443}
DEFAULT_SCHEMES = {"http", "https"}
_SCHEME_DEFAULT_PORT = {"http": 80, "https": 443}


def _normalize_host(host: str) -> str:
    host = (host or "").strip().rstrip(".").lower()
    if not host:
        raise ScopeViolation("empty host")
    # IDNA-normalize unicode hosts so homoglyph/punycode tricks can't slip past.
    try:
        host = host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        # Already ASCII or an IP literal; leave as-is.
        pass
    return host


def _as_ip(host: str):
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        return None


def _domain_matches(host: str, domain: str, include_subdomains: bool) -> bool:
    """True iff ``host`` is ``domain`` (or, when allowed, a subdomain of it),
    matched on label boundaries so suffixes can't be spoofed."""
    if host == domain:
        return True
    if include_subdomains and host.endswith("." + domain):
        return True
    return False


@dataclass(frozen=True)
class ScopeSpec:
    """Immutable authorized scope for a single scan.

    ``domains`` maps a registrable domain to whether its subdomains are in
    scope. ``hosts`` are exact hostnames (subdomains never implied).
    ``cidrs`` are authorized IP ranges — including, intentionally, the only way
    to authorize a private/internal range for an on-prem engagement.
    """

    domains: dict[str, bool] = field(default_factory=dict)
    hosts: frozenset[str] = field(default_factory=frozenset)
    cidrs: tuple[str, ...] = ()
    ports: frozenset[int] = field(default_factory=lambda: frozenset(DEFAULT_PORTS))
    schemes: frozenset[str] = field(default_factory=lambda: frozenset(DEFAULT_SCHEMES))

    @classmethod
    def from_target(
        cls,
        target_url: str,
        *,
        include_subdomains: bool = True,
        extra_hosts: list[str] | None = None,
        extra_cidrs: list[str] | None = None,
        extra_ports: list[int] | None = None,
    ) -> "ScopeSpec":
        """Build a scope from a single authorized target URL.

        The target's own host is always in scope. If it's a hostname,
        ``include_subdomains`` extends scope to its subdomains; if it's an IP,
        only that /32 (or /128) is authorized unless ``extra_cidrs`` widen it.
        """
        parts = urlsplit(target_url if "://" in target_url else "https://" + target_url)
        host = _normalize_host(parts.hostname or "")
        domains: dict[str, bool] = {}
        hosts: set[str] = set(h.lower() for h in (extra_hosts or []))
        cidrs: list[str] = list(extra_cidrs or [])

        ip = _as_ip(host)
        if ip is not None:
            cidrs.append(f"{ip}/{ip.max_prefixlen}")
        else:
            domains[host] = include_subdomains

        ports = set(DEFAULT_PORTS)
        if parts.port:
            ports.add(parts.port)
        ports.update(extra_ports or [])
        # validate cidrs now so a bad spec fails loudly at construction
        for c in cidrs:
            ipaddress.ip_network(c, strict=False)
        return cls(
            domains=domains,
            hosts=frozenset(hosts),
            cidrs=tuple(cidrs),
            ports=frozenset(ports),
        )

    def _port_for(self, scheme: str, explicit: int | None) -> int:
        return explicit if explicit is not None else _SCHEME_DEFAULT_PORT.get(scheme, 0)

    def contains_host(self, host: str) -> bool:
        host = _normalize_host(host)
        ip = _as_ip(host)
        if ip is not None:
            return any(ip in ipaddress.ip_network(c, strict=False) for c in self.cidrs)
        if host in self.hosts:
            return True
        return any(_domain_matches(host, d, sub) for d, sub in self.domains.items())

    def check(self, url: str) -> str:
        """Validate a full URL against scope. Returns the normalized host on
        success; raises :class:`ScopeViolation` otherwise."""
        parts = urlsplit(url)
        scheme = (parts.scheme or "").lower()
        if scheme not in self.schemes:
            raise ScopeViolation(f"scheme {scheme!r} not authorized")
        if parts.username or parts.password:
            raise ScopeViolation("credentials embedded in URL are not allowed")
        if not parts.hostname:
            raise ScopeViolation("URL has no host")
        host = _normalize_host(parts.hostname)
        port = self._port_for(scheme, parts.port)
        if port not in self.ports:
            raise ScopeViolation(f"port {port} not authorized (allowed: {sorted(self.ports)})")
        if not self.contains_host(host):
            raise ScopeViolation(f"host {host!r} is outside authorized scope")
        return host

    def is_in_scope(self, url: str) -> bool:
        try:
            self.check(url)
            return True
        except ScopeViolation:
            return False

    # --- persistence helpers ---
    def to_dict(self) -> dict:
        return {
            "domains": dict(self.domains),
            "hosts": sorted(self.hosts),
            "cidrs": list(self.cidrs),
            "ports": sorted(self.ports),
            "schemes": sorted(self.schemes),
        }

    @classmethod
    def from_dict(cls, d: dict) -> "ScopeSpec":
        return cls(
            domains=dict(d.get("domains", {})),
            hosts=frozenset(d.get("hosts", [])),
            cidrs=tuple(d.get("cidrs", [])),
            ports=frozenset(d.get("ports", DEFAULT_PORTS)),
            schemes=frozenset(d.get("schemes", DEFAULT_SCHEMES)),
        )

    def describe(self) -> str:
        parts = []
        for d, sub in self.domains.items():
            parts.append(f"{d}{' (+subdomains)' if sub else ''}")
        parts.extend(sorted(self.hosts))
        parts.extend(self.cidrs)
        return ", ".join(parts) or "(empty)"
