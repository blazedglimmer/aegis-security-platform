"""End-to-end: run the full agent pipeline against a deliberately vulnerable
loopback app and assert real, evidence-backed (and validated) findings.

The target app has: reflected XSS, a SQL-injection boolean oracle, missing
security headers, an insecure cookie, an exposed /.git/config, an unauthenticated
admin page, and an API leaking sensitive fields. This proves the platform
detects genuine issues from real HTTP evidence (no LLM, no external scanners).
"""

import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from backend.config import Settings
from backend.domain import FindingStatus, ScanStatus
from backend.orchestrator.graph import run_scan
from backend.orchestrator.state import ScanContext
from backend.safety import AuditLog, Budget, KillSwitch, RateLimiter, ScopeSpec
from backend.tools.llm import LLMClient


class VulnApp(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _send(self, body: bytes, status=200, ctype="text/html", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Server", "VulnServer/1.2.3")
        self.send_header("X-Powered-By", "PHP/7.4.1")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parts = urlsplit(self.path)
        path, qs = parts.path, parse_qs(parts.query)
        if path == "/":
            self._send(
                b'<html><body><h1>Shop</h1>'
                b'<a href="/search?q=test">search</a> '
                b'<a href="/item?id=1">item</a> '
                b'<a href="/api/users">users</a> '
                b'<a href="/admin">admin</a></body></html>',
                extra={"Set-Cookie": "session=abc123; Path=/"},  # insecure cookie
            )
        elif path == "/search":
            q = (qs.get("q") or [""])[0]
            self._send(f"<html><body>Results for: {q}</body></html>".encode())  # reflected XSS
        elif path == "/item":
            idv = (qs.get("id") or [""])[0]
            if "1=2" in idv or "1'='2" in idv:
                self._send(b"<html><body>No item found.</body></html>")          # FALSE branch
            elif "'" in idv and "1=1" not in idv and "1'='1" not in idv:
                self._send(b"<html><body>SQL syntax error near ''' at line 1 "
                           b"(MySQL)</body></html>", status=500)                   # error oracle
            else:
                self._send(b"<html><body>Item: Deluxe Widget, price 9.99</body></html>")  # TRUE/baseline
        elif path == "/.git/config":
            self._send(b"[core]\n\trepositoryformatversion = 0\n", ctype="text/plain")
        elif path == "/admin":
            self._send(b"<html><body><h1>Admin Dashboard</h1>Users, Settings</body></html>")
        elif path == "/api/users":
            self._send(b'[{"id":1,"email":"a@b.com","password":"x","token":"t","phone":"555"}]',
                       ctype="application/json")
        else:
            self._send(b"not found", status=404, ctype="text/plain")


@pytest.fixture()
def vuln_server():
    httpd = HTTPServer(("127.0.0.1", 0), VulnApp)
    port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield port
    httpd.shutdown()


def _ctx(port, tmp_path):
    target = f"http://127.0.0.1:{port}"
    scope = ScopeSpec.from_target(target)  # IP target → authorizes 127.0.0.1/32 + this port
    settings = Settings(enable_playwright=False, data_dir=tmp_path, reports_dir=tmp_path,
                        nuclei_path="/nonexistent-nuclei", zap_api_url=None)
    return ScanContext(
        scan_id="scan_e2e", authorization_id="authz_test", target_url=target, profile="safe",
        scope=scope, settings=settings, audit=AuditLog(tmp_path / "audit.jsonl"),
        budget=Budget(max_requests=2000), rate_limiter=RateLimiter(per_host_rps=100, burst=100),
        killswitch=KillSwitch(), llm=LLMClient(),
    )


@pytest.mark.asyncio
async def test_full_scan_finds_and_validates(vuln_server, tmp_path):
    ctx = _ctx(vuln_server, tmp_path)
    # Native runner path (no LangGraph dependency required for this assertion).
    state = await run_scan(ctx, ["web_vuln", "authz", "api"], use_langgraph=False)

    assert state["status"] == ScanStatus.COMPLETED.value
    findings = state["findings"]
    titles = " || ".join(f["title"].lower() for f in findings)

    # evidence-backed detections
    assert "content-security-policy" in titles
    assert "git/config" in titles or ".git" in titles
    assert "reflected input" in titles
    assert "sql" in titles
    assert "admin" in titles or "management interface" in titles
    assert "excessive data exposure" in titles or "sensitive fields" in titles

    # validation actually confirmed the injections non-destructively
    confirmed = [f for f in findings if f["status"] == FindingStatus.CONFIRMED.value]
    assert any("sql" in f["title"].lower() for f in confirmed), "SQLi should be confirmed by oracle"
    assert any("reflected" in f["title"].lower() for f in confirmed), "XSS should be confirmed"

    # CVSS computed by formula for scored findings
    assert any(f["cvss_score"] for f in findings)

    # audit log intact
    assert ctx.audit.verify() is True

    # a report was written in all three formats
    assert set(state["report_paths"]) == {"json", "md", "html"}


@pytest.mark.asyncio
async def test_scan_cannot_touch_offscope_host(vuln_server, tmp_path):
    """Even though the app links/redirects could point elsewhere, the guarded
    client refuses anything off-scope — proven here by a direct attempt."""
    ctx = _ctx(vuln_server, tmp_path)
    client = ctx.new_client()
    from backend.safety.errors import ScopeViolation
    try:
        with pytest.raises(ScopeViolation):
            await client.get("http://169.254.169.254/latest/meta-data/")
        with pytest.raises(ScopeViolation):
            await client.get("http://example.com/")
    finally:
        await client.aclose()
