"""Runtime configuration (env-driven via pydantic-settings)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AEGIS_", env_file=".env", extra="ignore")

    # --- storage ---
    data_dir: Path = ROOT / "data"
    reports_dir: Path = ROOT / "reports"
    db_url: str = f"sqlite+aiosqlite:///{ROOT / 'data' / 'aegis.db'}"

    # --- LLM (optional; platform runs tool-only without it) ---
    anthropic_api_key: str | None = None
    llm_model: str = "claude-opus-4-8"
    llm_max_tokens: int = 4096

    # --- authorization ---
    authorization_ttl_hours: int = 72
    verification_prefix: str = "aegis-site-verification"
    signing_secret: str = "change-me-in-production"  # HMAC for authz records

    # --- scan safety defaults ---
    default_per_host_rps: float = 4.0
    default_max_concurrency: int = 8
    default_request_budget: int = 5000
    default_time_budget_s: float = 3600.0

    # --- external tools (auto-detected if on PATH) ---
    nuclei_path: str = "nuclei"
    zap_api_url: str | None = None          # e.g. http://127.0.0.1:8080
    zap_api_key: str | None = None
    enable_playwright: bool = True

    def ensure_dirs(self) -> None:
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


@lru_cache
def get_settings() -> Settings:
    s = Settings()
    s.ensure_dirs()
    return s
