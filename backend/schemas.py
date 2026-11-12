"""API request/response schemas."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel


class AuthorizeRequest(BaseModel):
    target_url: str


class VerifyRequest(BaseModel):
    target_url: str
    method: Literal["dns", "file", "header"]
    operator: str = "unknown"
    include_subdomains: bool = True


class CreateScanRequest(BaseModel):
    authorization_id: str
    profile: Literal["passive", "safe", "aggressive"] = "safe"
    agents: list[str] = ["web_vuln", "authz", "api"]
