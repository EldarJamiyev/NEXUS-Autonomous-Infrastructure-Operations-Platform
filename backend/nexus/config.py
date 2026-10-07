"""Runtime configuration (environment variables / .env). No secrets have defaults."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AliasChoices, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


def _detect_config_root() -> Path:
    """Find the directory holding policies/ and baselines/ (repo root or /app in Docker)."""
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "policies").is_dir() and (parent / "baselines").is_dir():
            return parent
    return Path.cwd()


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="NEXUS_", env_file=".env", extra="ignore", populate_by_name=True)

    environment: Literal["simulation", "real-lab"] = Field("simulation", validation_alias=AliasChoices("NEXUS_ENV", "NEXUS_ENVIRONMENT"))
    database_url: str = Field("sqlite:///./data/nexus.db", validation_alias=AliasChoices("DATABASE_URL", "NEXUS_DATABASE_URL"))
    host: str = "0.0.0.0"
    port: int = 8000

    # Security. secret_key signs console tokens; when unset a random per-process key is generated.
    secret_key: str | None = None
    demo_auth: bool = True
    api_keys: str = ""  # "ROLE:token,ROLE:token" for non-demo deployments
    cors_origins: str = "http://localhost:5173,http://127.0.0.1:5173"
    rate_limit_per_minute: int = 60
    alertmanager_token: str | None = None

    # Control loop.
    autonomy_level: int = Field(3, ge=0, le=5)
    reconcile_interval: float = 20.0
    detection_interval: float = 2.0
    sim_tick_interval: float = 2.0
    snapshot_interval: float = 60.0
    snapshot_retention: int = 600
    step_delay_ms: int = 650
    background_tasks: bool = True
    seed_demo: bool = True
    seed_history: bool = True
    site_timezone: str = "Asia/Baku"

    # Adapters.
    firewall_adapter: Literal["mock", "pfsense"] = "mock"
    pfsense_url: str | None = Field(None, validation_alias=AliasChoices("PFSENSE_URL", "NEXUS_PFSENSE_URL"))
    pfsense_api_key: str | None = Field(None, validation_alias=AliasChoices("PFSENSE_API_KEY", "NEXUS_PFSENSE_API_KEY"))
    pfsense_verify_tls: bool = Field(True, validation_alias=AliasChoices("PFSENSE_VERIFY_TLS", "NEXUS_PFSENSE_VERIFY_TLS"))
    executor: Literal["simulated", "ansible"] = "simulated"
    ansible_inventory: str = "ansible/inventory/lab.ini"

    chatops_provider: Literal["none", "discord", "slack"] = Field("none", validation_alias=AliasChoices("CHATOPS_PROVIDER", "NEXUS_CHATOPS_PROVIDER"))
    chatops_webhook_url: str | None = Field(None, validation_alias=AliasChoices("CHATOPS_WEBHOOK_URL", "NEXUS_CHATOPS_WEBHOOK_URL"))

    log_level: str = "INFO"
    log_file: str | None = None
    config_root: Path = Field(default_factory=_detect_config_root)
    frontend_dist: Path | None = None

    @property
    def is_simulation(self) -> bool:
        return self.environment == "simulation"

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    def resolved_frontend_dist(self) -> Path | None:
        candidates = [self.frontend_dist] if self.frontend_dist else []
        candidates += [self.config_root / "frontend" / "dist", Path("/app/frontend_dist")]
        for c in candidates:
            if c and (c / "index.html").is_file():
                return c
        return None


@lru_cache
def get_settings() -> Settings:
    return Settings()
