"""nuclei wrapper — optional external scanner, safe-by-default.

Auto-detected on PATH. If absent, :meth:`available` is False and the caller
relies on the built-in passive checks / ZAP. When present:

* targets are **scope-validated** before they are handed to nuclei;
* destructive/noisy template tags are excluded (``dos``, ``intrusive``, ``fuzz``
  unless the aggressive profile is explicitly selected);
* request rate is capped to match the scan's throttle;
* the binary is invoked via an **argument vector** (never ``shell=True``), so
  target-derived strings can't be interpreted by a shell.

In production these external tools should run inside a network-restricted
sandbox (see ARCHITECTURE §6 Phase 6); this wrapper is the integration seam.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from pathlib import Path

from ..domain import Finding, Severity
from ..safety.scope import ScopeSpec

_SEV_MAP = {
    "info": Severity.INFO, "low": Severity.LOW, "medium": Severity.MEDIUM,
    "high": Severity.HIGH, "critical": Severity.CRITICAL, "unknown": Severity.INFO,
}


class NucleiScanner:
    def __init__(self, scope: ScopeSpec, *, binary: str = "nuclei",
                 per_host_rps: float = 4.0, profile: str = "safe"):
        self.scope = scope
        self.binary = shutil.which(binary) or (binary if Path(binary).exists() else None)
        self.rps = per_host_rps
        self.profile = profile

    @property
    def available(self) -> bool:
        return self.binary is not None

    def _excluded_tags(self) -> str:
        if self.profile == "aggressive":
            return "dos"
        return "dos,intrusive,fuzz,brute-force"

    async def scan(self, urls: list[str], *, extra_tags: str | None = None,
                   timeout: float = 600.0) -> list[Finding]:
        if not self.available:
            return []
        in_scope = [u for u in urls if self.scope.is_in_scope(u)]
        if not in_scope:
            return []

        with tempfile.TemporaryDirectory() as td:
            targets_file = Path(td) / "targets.txt"
            targets_file.write_text("\n".join(sorted(set(in_scope))))
            out_file = Path(td) / "out.jsonl"

            args = [
                self.binary,
                "-list", str(targets_file),
                "-jsonl", "-output", str(out_file),
                "-etags", self._excluded_tags(),
                "-rate-limit", str(int(max(1, self.rps))),
                "-no-interactsh",            # no outbound OOB callbacks
                "-disable-update-check",
                "-silent",
                "-timeout", "10",
            ]
            if extra_tags:
                args += ["-tags", extra_tags]

            try:
                proc = await asyncio.create_subprocess_exec(
                    *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
                )
                await asyncio.wait_for(proc.communicate(), timeout=timeout)
            except (asyncio.TimeoutError, FileNotFoundError, OSError):
                return []

            return self._parse(out_file)

    def _parse(self, out_file: Path) -> list[Finding]:
        if not out_file.exists():
            return []
        findings: list[Finding] = []
        for line in out_file.read_text().splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                r = json.loads(line)
            except json.JSONDecodeError:
                continue
            info = r.get("info", {})
            matched = r.get("matched-at") or r.get("host") or ""
            # Defense in depth: drop anything that drifted out of scope.
            if matched and not self.scope.is_in_scope(matched if "://" in matched else "https://" + matched):
                continue
            sev = _SEV_MAP.get(str(info.get("severity", "info")).lower(), Severity.INFO)
            cvss_vector = None
            classification = info.get("classification") or {}
            if isinstance(classification, dict):
                cvss_vector = classification.get("cvss-metrics")
            findings.append(Finding(
                agent="web_vuln",
                title=info.get("name", r.get("template-id", "nuclei finding")),
                severity=sev,
                category=self._category(info),
                endpoint=matched,
                description=info.get("description", "") or f"nuclei template {r.get('template-id')}",
                cvss_vector=cvss_vector,
                confidence="high" if sev.rank >= Severity.MEDIUM.rank else "medium",
                remediation=info.get("remediation", "") or "Review the matched template guidance.",
                references=info.get("reference", []) or [],
                evidence={
                    "template_id": r.get("template-id"),
                    "matched_at": matched,
                    "extracted": r.get("extracted-results"),
                    "type": r.get("type"),
                    "matcher_name": r.get("matcher-name"),
                    "tool": "nuclei",
                },
            ))
        return findings

    @staticmethod
    def _category(info: dict) -> str:
        tags = info.get("tags") or []
        tagset = set(t.lower() for t in tags) if isinstance(tags, list) else set()
        if {"sqli", "sql-injection"} & tagset:
            return "A03:2021-Injection"
        if {"xss"} & tagset:
            return "A03:2021-Injection"
        if {"ssrf"} & tagset:
            return "A10:2021-Server-Side Request Forgery"
        if {"exposure", "disclosure", "config"} & tagset:
            return "A05:2021-Security Misconfiguration"
        if {"cve"} & tagset:
            return "A06:2021-Vulnerable and Outdated Components"
        if {"default-login", "auth-bypass"} & tagset:
            return "A07:2021-Identification and Authentication Failures"
        return "misc"
