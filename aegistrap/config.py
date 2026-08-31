"""Runtime configuration, loaded from environment / .env with safe defaults.

Defaults are chosen so that a bare `uvicorn aegistrap.main:app` works with no
API keys and no network access.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

ProviderName = Literal["offline", "anthropic", "openai", "ollama"]
PersonaName = Literal["fintech", "ecommerce"]

REPO_ROOT = Path(__file__).resolve().parent.parent


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGISTRAP_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM response engine -------------------------------------------------
    llm_provider: ProviderName = "offline"

    anthropic_api_key: str = ""
    anthropic_model: str = "claude-sonnet-4-20250514"
    anthropic_base_url: str = "https://api.anthropic.com"

    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    openai_base_url: str = "https://api.openai.com"

    ollama_base_url: str = "http://localhost:11434"
    ollama_model: str = "llama3.1:8b"

    #: Provider for the threat-intel reporter; empty means reuse ``llm_provider``.
    reporter_provider: str = ""

    llm_timeout_seconds: float = 12.0
    llm_max_output_tokens: int = 1200
    llm_temperature: float = 0.4
    llm_cache_enabled: bool = True
    llm_cache_ttl_seconds: int = 900

    # --- deception behaviour -------------------------------------------------
    persona: PersonaName = "fintech"
    adaptive_deception: bool = True
    fingerprint_evasion: bool = False

    #: Simulated backend latency floor, so LLM calls do not stand out as slow.
    #: See Section 13 (latency tipping off attackers).
    latency_floor_ms: int = 40
    latency_jitter_ms: int = 90

    # --- storage / reporting ------------------------------------------------
    db_path: Path = Path("data/aegistrap.sqlite3")
    report_dir: Path = Path("reports")
    session_idle_seconds: int = 300
    auto_report_enabled: bool = True
    report_sweep_seconds: int = 60

    # --- ethics / data handling (Section 10) --------------------------------
    anonymise_ips: bool = False
    log_retention_days: int = 90
    max_body_capture_bytes: int = 8192

    # --- dashboard ----------------------------------------------------------
    dashboard_enabled: bool = True
    dashboard_token: str = ""

    # --- deployment banner --------------------------------------------------
    service_name: str = "Northwind Capital API"
    service_version: str = "2.4.1"

    #: ``Server`` header presented when fingerprint evasion is off. A real API
    #: of this kind sits behind a reverse proxy, so the honeypot must never
    #: advertise its own ASGI runtime — that alone narrows an attacker's guess
    #: to a Python service and is a strong honeypot tell.
    server_banner: str = "nginx"

    log_level: str = Field(default="INFO")

    @field_validator("db_path", "report_dir", mode="after")
    @classmethod
    def _absolutise(cls, value: Path) -> Path:
        return value if value.is_absolute() else REPO_ROOT / value

    @property
    def effective_reporter_provider(self) -> ProviderName:
        candidate = (self.reporter_provider or "").strip().lower()
        if candidate in ("offline", "anthropic", "openai", "ollama"):
            return candidate  # type: ignore[return-value]
        return self.llm_provider

    def provider_is_configured(self, provider: str) -> bool:
        """Whether the named provider has the credentials it needs."""
        if provider == "offline":
            return True
        if provider == "anthropic":
            return bool(self.anthropic_api_key)
        if provider == "openai":
            return bool(self.openai_api_key)
        if provider == "ollama":
            return bool(self.ollama_base_url)
        return False

    def ensure_directories(self) -> None:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.report_dir.mkdir(parents=True, exist_ok=True)


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    settings = Settings()
    settings.ensure_directories()
    return settings


def reset_settings_cache() -> None:
    """Test hook: forget the cached singleton so env changes take effect."""
    get_settings.cache_clear()
