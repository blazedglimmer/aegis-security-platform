"""Payload safety blocklist for the Exploitation Validation agent.

Validation must be *non-destructive and idempotent*. Every PoC payload is run
through :func:`assert_non_destructive` before it is sent; anything that could
modify data, exfiltrate, cause delay/DoS, or run commands is refused — even if
an agent (or a prompt-injected page) tried to construct it.

The validator is allowed only a tiny vocabulary of read-only oracles:
  * XSS: reflect a unique benign nonce and inspect the reflection *context*
    (we never execute script, we analyze encoding);
  * SQLi: a boolean oracle using ``AND 1=1`` / ``AND 1=2`` (no UNION, no stacked
    queries, no time-based, no reads of data).
"""

from __future__ import annotations

import re

from .errors import SafetyError


class DestructivePayloadBlocked(SafetyError):
    pass


# Patterns that must never appear in a validation payload.
_BLOCKLIST = [
    r"\bunion\b\s+\bselect\b",              # data extraction
    r"\b(drop|truncate|alter|create)\b\s+\b(table|database|schema)\b",
    r"\b(insert|update|delete)\b\s+(into|from|set)?",  # writes
    r";\s*(shutdown|drop|delete|update|insert)",        # stacked destructive
    r"\b(sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe)\b",  # time/DoS
    r"\b(load_file|into\s+outfile|into\s+dumpfile)\b",   # file read/write
    r"\bxp_cmdshell\b|\bsp_oacreate\b",                  # command exec
    r"(^|\s)(rm|mkfs|dd|shutdown|reboot|kill)\s",        # OS commands
    r"\.\./\.\./",                                        # path traversal depth
    r"(curl|wget|nslookup|dig)\s",                       # OOB exfil / callbacks
    r"burpcollaborator|interact\.sh|oast|\.oastify\.",   # OOB callback hosts
    r"<script[^>]*>[^<]*(document\.cookie|fetch|xmlhttprequest|location)", # exfil JS
]
_COMPILED = [re.compile(p, re.I) for p in _BLOCKLIST]

# The only SQL boolean oracle tokens the validator may use.
SAFE_SQL_TRUE = "' AND '1'='1"
SAFE_SQL_FALSE = "' AND '1'='2"
SAFE_SQL_TRUE_NUM = " AND 1=1"
SAFE_SQL_FALSE_NUM = " AND 1=2"


def is_destructive(payload: str) -> bool:
    return any(p.search(payload or "") for p in _COMPILED)


def assert_non_destructive(payload: str) -> None:
    if is_destructive(payload):
        raise DestructivePayloadBlocked(
            f"refusing payload containing a destructive/exfil pattern: {payload[:80]!r}"
        )
