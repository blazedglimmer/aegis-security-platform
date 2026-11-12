"""SQLModel persistence tables. Complex structures are stored as JSON columns;
the canonical in-memory shapes live in ``domain.py`` / ``safety/authorization.py``.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from sqlalchemy import JSON, Column
from sqlmodel import Field, SQLModel


def _now() -> datetime:
    return datetime.now(timezone.utc)


class AuthorizationRecord(SQLModel, table=True):
    __tablename__ = "authorizations"
    id: str = Field(primary_key=True)
    target_url: str
    host: str = Field(index=True)
    method: str
    operator: str = "unknown"
    scope: dict = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)
    expires_at: datetime
    signature: str = ""


class ScanRecord(SQLModel, table=True):
    __tablename__ = "scans"
    id: str = Field(primary_key=True)
    authorization_id: str = Field(index=True)
    target_url: str
    profile: str = "safe"
    status: str = "created"
    selected_agents: list = Field(default_factory=list, sa_column=Column(JSON))
    stats: dict = Field(default_factory=dict, sa_column=Column(JSON))
    error: str | None = None
    created_at: datetime = Field(default_factory=_now)
    started_at: datetime | None = None
    finished_at: datetime | None = None


class FindingRecord(SQLModel, table=True):
    __tablename__ = "findings"
    id: str = Field(primary_key=True)
    scan_id: str = Field(index=True)
    agent: str
    title: str
    severity: str = "info"
    category: str = "misc"
    status: str = "candidate"
    cvss_score: float | None = None
    dedup_key: str = Field(index=True)
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
    created_at: datetime = Field(default_factory=_now)


class EventRecord(SQLModel, table=True):
    __tablename__ = "events"
    id: str = Field(primary_key=True)
    scan_id: str = Field(index=True)
    ts: datetime = Field(default_factory=_now)
    agent: str = "orchestrator"
    type: str = "log"
    message: str = ""
    data: dict[str, Any] = Field(default_factory=dict, sa_column=Column(JSON))
