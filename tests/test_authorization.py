"""Authorization verification (file + header) and record signing."""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from backend.safety import AuditLog, Budget, KillSwitch, RateLimiter, ScopeSpec, SSRFGuard
from backend.safety.authorization import AuthorizationService, VerificationError, make_token
from backend.tools.http_client import GuardedHttpClient

SECRET = "test-secret"


def _token_for(port):
    return make_token(f"http://target.test:{port}", SECRET)


class _Handler(BaseHTTPRequestHandler):
    token = ""

    def log_message(self, *a):
        pass

    def do_GET(self):
        if self.path == "/.well-known/aegis-authorization.txt":
            body = self.token.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(200)
        self.send_header("X-Aegis-Authorization", self.token)
        self.send_header("Content-Length", "2")
        self.end_headers()
        self.wfile.write(b"ok")


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), _Handler)
    port = httpd.server_address[1]
    _Handler.token = _token_for(port)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield port
    httpd.shutdown()


def _factory(port):
    def make(scope, ssrf):
        # force loopback resolution + authorize it for the test
        scope2 = ScopeSpec.from_target(f"http://target.test:{port}", extra_cidrs=["127.0.0.1/32"])
        ssrf2 = SSRFGuard(scope2, resolver=lambda h: [(socket.AF_INET, "127.0.0.1")])
        return GuardedHttpClient(
            scope=scope2, ssrf=ssrf2,
            rate_limiter=RateLimiter(per_host_rps=50, burst=50),
            budget=Budget(max_requests=20),
            audit=AuditLog(f"/tmp/aegis-authz-{port}.jsonl"),
            killswitch=KillSwitch(), scan_id="verify", verify_tls=False,
        )
    return make


@pytest.mark.asyncio
async def test_file_verification_succeeds_and_signs(server):
    port = server
    svc = AuthorizationService(SECRET, ttl_hours=1)
    authz = await svc.verify(
        f"http://target.test:{port}", "file",
        http_client_factory=_factory(port), operator="alice",
    )
    assert authz.is_valid()
    assert authz.verify_signature(SECRET)
    assert not authz.verify_signature("wrong-secret")
    # scope round-trips
    assert authz.scope_spec().is_in_scope(f"http://target.test:{port}/x")


@pytest.mark.asyncio
async def test_header_verification_succeeds(server):
    port = server
    svc = AuthorizationService(SECRET, ttl_hours=1)
    authz = await svc.verify(
        f"http://target.test:{port}", "header", http_client_factory=_factory(port),
    )
    assert authz.method == "header"


@pytest.mark.asyncio
async def test_wrong_token_fails(server):
    port = server
    _Handler.token = "aegis-not-the-real-token"
    svc = AuthorizationService(SECRET, ttl_hours=1)
    with pytest.raises(VerificationError):
        await svc.verify(
            f"http://target.test:{port}", "header", http_client_factory=_factory(port),
        )
    _Handler.token = _token_for(port)


def test_signature_tamper_detected(server):
    port = server
    svc = AuthorizationService(SECRET, ttl_hours=1)
    import asyncio
    authz = asyncio.get_event_loop().run_until_complete(
        svc.verify(f"http://target.test:{port}", "file", http_client_factory=_factory(port))
    )
    authz.operator = "mallory"          # tamper after signing
    assert not authz.verify_signature(SECRET)
