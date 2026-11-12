"""AuditLog — tamper-evident, append-only record of everything that matters.

Every authorization decision, outbound request, tool invocation, and finding is
appended as one JSON line whose ``hash`` chains the previous line's hash
(``hash_n = sha256(prev_hash || canonical(record))``). Any edit or deletion of
an earlier line breaks the chain and is detectable by :meth:`verify`.

Sensitive values (cookies, authorization headers, token-like strings) are
redacted before they are ever written.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from pathlib import Path
from typing import Any

_GENESIS = "0" * 64

_REDACT_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "proxy-authorization"}
_TOKENISH = re.compile(
    r"(?i)(bearer\s+[a-z0-9._\-]+|eyJ[a-zA-Z0-9._\-]{10,}|[a-z0-9]{32,})"
)


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        out = {}
        for k, v in value.items():
            if k.lower() in _REDACT_HEADERS:
                out[k] = "<redacted>"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(value, list):
        return [_redact(v) for v in value]
    if isinstance(value, str):
        return _TOKENISH.sub("<redacted-token>", value)
    return value


def _canonical(record: dict) -> str:
    return json.dumps(record, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


class AuditLog:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._recover_last_hash()

    def _recover_last_hash(self) -> str:
        if not self.path.exists():
            return _GENESIS
        last = _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        last = json.loads(line)["hash"]
                    except (json.JSONDecodeError, KeyError):
                        continue
        return last

    def append(self, event_type: str, payload: dict | None = None, **fields) -> dict:
        record = {
            "ts": time.time(),
            "type": event_type,
            **fields,
            "payload": _redact(payload or {}),
        }
        body = _canonical({k: v for k, v in record.items()})
        with self._lock:
            chained = hashlib.sha256((self._last_hash + body).encode("utf-8")).hexdigest()
            record["prev"] = self._last_hash
            record["hash"] = chained
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(_canonical(record) + "\n")
            self._last_hash = chained
        return record

    def verify(self) -> bool:
        """Re-walk the chain; return True iff intact.

        Mirrors :meth:`append`: the hashed body is the record with ``prev`` and
        ``hash`` removed, and ``hash == sha256(prev || canonical(body))``.
        """
        prev = _GENESIS
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                record = json.loads(line)
                stored = record.get("hash")
                claimed_prev = record.get("prev")
                if claimed_prev != prev:
                    return False
                body = _canonical({k: v for k, v in record.items() if k not in ("prev", "hash")})
                recomputed = hashlib.sha256((prev + body).encode("utf-8")).hexdigest()
                if recomputed != stored:
                    return False
                prev = stored
        return True
