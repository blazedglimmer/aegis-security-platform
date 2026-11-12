"""Tests for the safety core. These are the most important tests in the repo:
if any of these regress, the scanner can go out of scope or hit internal
infrastructure, so CI must treat a failure here as release-blocking.
"""

import ipaddress
import socket

import pytest

from backend.safety.errors import BudgetExceeded, ScopeViolation, SSRFBlocked
from backend.safety.ratelimit import Budget
from backend.safety.scope import ScopeSpec
from backend.safety.ssrf import SSRFGuard


# --------------------------------------------------------------------------- scope
def test_scope_allows_target_and_subdomains():
    s = ScopeSpec.from_target("https://example.com", include_subdomains=True)
    assert s.is_in_scope("https://example.com/")
    assert s.is_in_scope("https://api.example.com/v1")
    assert s.is_in_scope("http://example.com/")  # default ports


def test_scope_denies_lookalikes_and_suffix_tricks():
    s = ScopeSpec.from_target("https://example.com")
    assert not s.is_in_scope("https://evil-example.com/")
    assert not s.is_in_scope("https://example.com.attacker.net/")
    assert not s.is_in_scope("https://notexample.com/")


def test_scope_denies_subdomains_when_opted_out():
    s = ScopeSpec.from_target("https://example.com", include_subdomains=False)
    assert s.is_in_scope("https://example.com/")
    assert not s.is_in_scope("https://api.example.com/")


def test_scope_rejects_bad_scheme_port_and_creds():
    s = ScopeSpec.from_target("https://example.com")
    with pytest.raises(ScopeViolation):
        s.check("ftp://example.com/")
    with pytest.raises(ScopeViolation):
        s.check("https://example.com:8443/")        # port not authorized
    with pytest.raises(ScopeViolation):
        s.check("https://user:pass@example.com/")   # creds in URL


def test_scope_custom_port_authorized_from_target():
    s = ScopeSpec.from_target("https://example.com:8443")
    assert s.is_in_scope("https://example.com:8443/")
    assert s.is_in_scope("https://example.com/")        # 443 still ok


def test_scope_ip_target_is_slash32_only():
    s = ScopeSpec.from_target("http://203.0.113.5")
    assert s.is_in_scope("http://203.0.113.5/")
    assert not s.is_in_scope("http://203.0.113.6/")


def test_scope_idna_normalization():
    s = ScopeSpec.from_target("https://example.com")
    # trailing dot / uppercase must normalize to the same host
    assert s.is_in_scope("https://EXAMPLE.com./")


# --------------------------------------------------------------------------- ssrf
def _resolver(mapping):
    def _r(host):
        if host not in mapping:
            raise socket.gaierror("NXDOMAIN")
        return [(socket.AF_INET, ip) for ip in mapping[host]]
    return _r


def test_ssrf_allows_public_ip():
    scope = ScopeSpec.from_target("https://example.com")
    guard = SSRFGuard(scope, resolver=_resolver({"example.com": ["93.184.216.34"]}))
    pinned = guard.resolve_and_pin("example.com")
    assert pinned.ip == "93.184.216.34"


@pytest.mark.parametrize("addr", ["127.0.0.1", "169.254.169.254", "10.0.0.5", "192.168.1.1", "0.0.0.0"])
def test_ssrf_blocks_private_and_metadata(addr):
    scope = ScopeSpec.from_target("https://example.com")
    guard = SSRFGuard(scope, resolver=_resolver({"example.com": [addr]}))
    with pytest.raises(SSRFBlocked):
        guard.resolve_and_pin("example.com")


def test_ssrf_blocks_mixed_answer_with_internal_ip():
    # DNS returns one public + one internal; must reject the whole answer.
    scope = ScopeSpec.from_target("https://example.com")
    guard = SSRFGuard(scope, resolver=_resolver({"example.com": ["93.184.216.34", "10.1.2.3"]}))
    with pytest.raises(SSRFBlocked):
        guard.resolve_and_pin("example.com")


def test_ssrf_allows_private_only_when_cidr_authorized():
    # On-prem engagement: operator explicitly authorized 10.10.0.0/16.
    scope = ScopeSpec.from_target("https://box.internal", extra_cidrs=["10.10.0.0/16"])
    guard = SSRFGuard(scope, resolver=_resolver({"box.internal": ["10.10.5.5"]}))
    pinned = guard.resolve_and_pin("box.internal")
    assert pinned.ip == "10.10.5.5"
    # ...but metadata is still blocked even if a CIDR tried to include it.
    scope2 = ScopeSpec.from_target("https://x.internal", extra_cidrs=["169.254.0.0/16"])
    guard2 = SSRFGuard(scope2, resolver=_resolver({"x.internal": ["169.254.169.254"]}))
    with pytest.raises(SSRFBlocked):
        guard2.resolve_and_pin("x.internal")


# --------------------------------------------------------------------------- budget
def test_budget_enforced():
    b = Budget(max_requests=3)
    b.spend(); b.spend(); b.spend()
    with pytest.raises(BudgetExceeded):
        b.spend()
    assert b.used == 3
