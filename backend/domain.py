"""Domain types shared by agents, orchestrator, API, and reports.

These are plain Pydantic models used in-memory on the LangGraph state and
serialized into JSON columns for persistence (see ``models.py``).
"""

from __future__ import annotations

import enum
import hashlib
import uuid
from datetime import datetime, timezone
from typing import Any, Literal

from pydantic import BaseModel, Field


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _uid(prefix: str) -> str:
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}[self.value]


class FindingStatus(str, enum.Enum):
    CANDIDATE = "candidate"        # proposed by an assessment agent, unverified
    VALIDATED = "validated"        # confirmed by non-destructive PoC
    CONFIRMED = "confirmed"        # analysis agent accepted it
    FALSE_POSITIVE = "false_positive"
    INFORMATIONAL = "informational"


class ScanStatus(str, enum.Enum):
    CREATED = "created"
    AUTHORIZING = "authorizing"
    RUNNING = "running"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Tech(BaseModel):
    name: str
    version: str | None = None
    category: str | None = None          # server, framework, cms, language, cdn...
    evidence: str | None = None


class Endpoint(BaseModel):
    url: str
    method: str = "GET"
    status: int | None = None
    content_type: str | None = None
    params: list[str] = Field(default_factory=list)
    source: str = "crawl"                # crawl, sitemap, robots, link, form, api
    notes: str | None = None

    @property
    def key(self) -> str:
        return f"{self.method} {self.url}"


class Lead(BaseModel):
    """A suspicious surface one agent wants another to investigate further."""
    kind: str                            # login_form, graphql, upload, idor_candidate...
    target: str
    rationale: str
    suggested_agent: str | None = None


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: _uid("find"))
    agent: str
    title: str
    severity: Severity = Severity.INFO
    category: str = "misc"               # OWASP category, e.g. "A03:2021-Injection"
    endpoint: str | None = None
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)
    reproduction: list[str] = Field(default_factory=list)
    impact: str = ""
    remediation: str = ""
    confidence: Literal["low", "medium", "high"] = "medium"
    status: FindingStatus = FindingStatus.CANDIDATE
    cvss_vector: str | None = None
    cvss_score: float | None = None
    references: list[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=_now)

    @property
    def dedup_key(self) -> str:
        """Stable identity for dedup across agents: (category, normalized title,
        endpoint path)."""
        base = f"{self.category}|{self.title.lower().strip()}|{(self.endpoint or '').split('?')[0]}"
        return hashlib.sha256(base.encode()).hexdigest()[:16]


class Event(BaseModel):
    id: str = Field(default_factory=lambda: _uid("evt"))
    scan_id: str
    ts: datetime = Field(default_factory=_now)
    agent: str = "orchestrator"
    type: str = "log"                    # log, agent_start, agent_end, finding, error, status
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
