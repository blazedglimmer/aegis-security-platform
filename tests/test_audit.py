"""Audit log: hash chain integrity, tamper detection, and secret redaction."""

import json

from backend.safety.audit import AuditLog


def test_chain_verifies_and_detects_tampering(tmp_path):
    log = AuditLog(tmp_path / "audit.jsonl")
    log.append("authorization", {"target": "example.com"}, scan_id="s1")
    log.append("http_request", {"url": "https://example.com/"}, scan_id="s1")
    log.append("finding", {"name": "missing header"}, scan_id="s1")
    assert log.verify() is True

    # Tamper with a middle line.
    lines = (tmp_path / "audit.jsonl").read_text().splitlines()
    rec = json.loads(lines[1])
    rec["payload"]["url"] = "https://attacker.example/"
    lines[1] = json.dumps(rec, sort_keys=True, separators=(",", ":"))
    (tmp_path / "audit.jsonl").write_text("\n".join(lines) + "\n")

    assert log.verify() is False


def test_recover_last_hash_across_reopen(tmp_path):
    p = tmp_path / "audit.jsonl"
    a = AuditLog(p)
    a.append("x", {"a": 1})
    b = AuditLog(p)              # reopen: must continue the chain, not reset
    b.append("y", {"b": 2})
    assert AuditLog(p).verify() is True


def test_secret_redaction():
    from backend.safety.audit import _redact
    out = _redact({
        "Authorization": "Bearer abcdef.ghijkl.mnopqr",
        "Cookie": "session=deadbeef",
        "note": "token eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9",
        "nested": {"x-api-key": "k"},
    })
    assert out["Authorization"] == "<redacted>"
    assert out["Cookie"] == "<redacted>"
    assert "<redacted-token>" in out["note"]
    assert out["nested"]["x-api-key"] == "<redacted>"
