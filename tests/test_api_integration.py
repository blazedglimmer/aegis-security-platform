"""Full backend integration over the real ASGI app (REST flow).

Starts a loopback target that (a) serves the Aegis verification token so
ownership can be proven, and (b) contains real vulnerabilities. Then drives the
public API: get token → verify → create scan → start → poll → findings → report.
"""

import os
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

# Configure the app BEFORE importing it (settings are cached).
_TMP = tempfile.mkdtemp()
os.environ["AEGIS_DB_URL"] = f"sqlite+aiosqlite:///{_TMP}/test.db"
os.environ["AEGIS_DATA_DIR"] = _TMP
os.environ["AEGIS_REPORTS_DIR"] = _TMP
os.environ["AEGIS_ENABLE_PLAYWRIGHT"] = "false"
os.environ["AEGIS_NUCLEI_PATH"] = "/nonexistent-nuclei"

import httpx  # noqa: E402

from backend.config import get_settings  # noqa: E402
from backend.db import init_db  # noqa: E402
from backend.main import app  # noqa: E402
from backend.safety.authorization import make_token  # noqa: E402

SECRET = get_settings().signing_secret


class Target(BaseHTTPRequestHandler):
    port = 0

    def log_message(self, *a):
        pass

    def _send(self, body, status=200, ctype="text/html", extra=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path = urlsplit(self.path).path
        qs = parse_qs(urlsplit(self.path).query)
        token = make_token(f"http://127.0.0.1:{Target.port}", SECRET)
        if path == "/.well-known/aegis-authorization.txt":
            self._send(token.encode(), ctype="text/plain")
        elif path == "/":
            self._send(b'<html><body><a href="/search?q=1">s</a>'
                       b'<a href="/.git/config">g</a></body></html>',
                       extra={"Set-Cookie": "sid=xyz; Path=/"})
        elif path == "/search":
            q = (qs.get("q") or [""])[0]
            self._send(f"<html>q={q}</html>".encode())
        elif path == "/.git/config":
            self._send(b"[core]\n\trepositoryformatversion = 0\n", ctype="text/plain")
        else:
            self._send(b"nf", status=404, ctype="text/plain")


@pytest.fixture()
def target():
    httpd = HTTPServer(("127.0.0.1", 0), Target)
    Target.port = httpd.server_address[1]
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield Target.port
    httpd.shutdown()


@pytest.mark.asyncio
async def test_api_end_to_end(target):
    await init_db()
    base = f"http://127.0.0.1:{target}"
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://app") as c:
        # 1) token + instructions
        r = await c.post("/api/authorizations", json={"target_url": base})
        assert r.status_code == 200 and r.json()["token"].startswith("aegis-")

        # 2) verify ownership via the well-known file
        r = await c.post("/api/authorizations/verify",
                         json={"target_url": base, "method": "file", "operator": "tester"})
        assert r.status_code == 200, r.text
        authz_id = r.json()["authorization_id"]

        # 3) create + start scan
        r = await c.post("/api/scans", json={"authorization_id": authz_id,
                                             "profile": "safe", "agents": ["web_vuln", "authz"]})
        assert r.status_code == 200, r.text
        scan_id = r.json()["scan_id"]
        r = await c.post(f"/api/scans/{scan_id}/start")
        assert r.status_code == 200

        # 4) poll to completion (background task shares this event loop)
        import asyncio
        for _ in range(60):
            s = (await c.get(f"/api/scans/{scan_id}")).json()
            if s["status"] in ("completed", "failed", "stopped"):
                break
            await asyncio.sleep(0.3)
        assert s["status"] == "completed", s

        # 5) findings + report
        findings = (await c.get(f"/api/scans/{scan_id}/findings")).json()
        titles = " ".join(f["title"].lower() for f in findings)
        assert "git" in titles and "content-security-policy" in titles
        rep = await c.get(f"/api/scans/{scan_id}/report.html")
        assert rep.status_code == 200 and b"Security Assessment Report" in rep.content


@pytest.mark.asyncio
async def test_scan_rejected_without_authorization(target):
    await init_db()
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://app") as c:
        r = await c.post("/api/scans", json={"authorization_id": "authz_does_not_exist",
                                             "profile": "safe", "agents": ["web_vuln"]})
        assert r.status_code == 400
