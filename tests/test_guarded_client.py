"""End-to-end GuardedHttpClient tests against a real loopback HTTP server.

These prove the *integration*: a request to an authorized host whose name
resolves to a public IP works, but if the SSRF resolver points the host at a
blocked address the client refuses before connecting; and an out-of-scope
redirect is not followed.
"""

import asyncio
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from backend.safety import (
    AuditLog,
    Budget,
    KillSwitch,
    RateLimiter,
    ScopeSpec,
    SSRFBlocked,
    SSRFGuard,
)
from backend.tools.http_client import GuardedHttpClient


class _Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/redirect-offscope":
            self.send_response(302)
            self.send_header("Location", "http://offscope.test/")
            self.end_headers()
            return
        body = b"hello from target"
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield port
    httpd.shutdown()


def _make_client(port, resolver, scope=None):
    scope = scope or ScopeSpec.from_target(
        f"http://target.test:{port}", extra_cidrs=["127.0.0.1/32"]
    )
    audit = AuditLog(f"/tmp/aegis-test-audit-{port}.jsonl")
    return GuardedHttpClient(
        scope=scope,
        ssrf=SSRFGuard(scope, resolver=resolver),
        rate_limiter=RateLimiter(per_host_rps=50, burst=50),
        budget=Budget(max_requests=50),
        audit=audit,
        killswitch=KillSwitch(),
        scan_id="test",
        verify_tls=False,
    )


@pytest.mark.asyncio
async def test_request_to_authorized_host_pinned_to_loopback(server):
    port = server
    # target.test "resolves" to loopback, which is authorized via extra_cidrs.
    resolver = lambda h: [(socket.AF_INET, "127.0.0.1")]
    client = _make_client(port, resolver)
    try:
        ex = await client.get(f"http://target.test:{port}/")
        assert ex.status == 200
        assert ex.text == "hello from target"
        assert ex.resolved_ip == "127.0.0.1"
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_rebind_to_blocked_ip_is_refused(server):
    port = server
    scope = ScopeSpec.from_target(f"http://target.test:{port}")  # no private CIDR authorized
    resolver = lambda h: [(socket.AF_INET, "169.254.169.254")]
    client = _make_client(port, resolver, scope=scope)
    try:
        with pytest.raises(SSRFBlocked):
            await client.get(f"http://target.test:{port}/")
    finally:
        await client.aclose()


@pytest.mark.asyncio
async def test_offscope_redirect_not_followed(server):
    port = server
    resolver = lambda h: [(socket.AF_INET, "127.0.0.1")]
    client = _make_client(port, resolver)
    try:
        ex = await client.get(f"http://target.test:{port}/redirect-offscope")
        # We stop at the redirect and return it as evidence rather than following.
        assert ex.status == 302
        assert "offscope.test" not in ex.text
    finally:
        await client.aclose()
