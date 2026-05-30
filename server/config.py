"""Server configuration loaded from environment and config file."""

from typing import Any
from pydantic import field_validator
from pydantic_settings import BaseSettings

try:
    from pydantic_settings import SettingsConfigDict
except ImportError:  # pragma: no cover - pydantic-settings v1 fallback
    SettingsConfigDict = None


class Settings(BaseSettings):
    """Server settings with environment variable and .env file support."""

    SERVER_HOST: str = "0.0.0.0"
    SERVER_PORT: int = 8000
    DATABASE_URL: str = "sqlite:///./miniedr.db"
    AUTH_TOKEN: str | None = None  # optional Bearer token for agent authentication
    VT_ENABLED: bool = True
    VT_API_KEY: str | None = None
    GLPI_ENABLED: bool = False
    GLPI_WEB_URL: str = "https://glpi.lockbits.pro"
    GLPI_API_URL: str = "https://glpi.lockbits.pro/api.php/v2.2"
    GLPI_OAUTH_CLIENT_ID: str | None = None
    GLPI_OAUTH_CLIENT_SECRET: str | None = None
    GLPI_API_USERNAME: str | None = None
    GLPI_API_PASSWORD: str | None = None
    GLPI_APP_TOKEN: str | None = None
    GLPI_USER_TOKEN: str | None = None
    GLPI_TICKET_ENTITY_ID: int | None = None
    GLPI_TICKET_CATEGORY_ID: int | None = None
    GLPI_REQUESTER_ID: int | None = None
    GLPI_TIMEOUT_SECONDS: float = 10.0

    @field_validator("GLPI_TICKET_ENTITY_ID", "GLPI_TICKET_CATEGORY_ID", "GLPI_REQUESTER_ID", mode="before")
    @classmethod
    def empty_str_to_none(cls, v: Any) -> Any:
        if v == "":
            return None
        return v

    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "*"  # comma-separated list of allowed origins, or "*" for all
    MAX_EVENTS_PER_PAGE: int = 100
    WORKERS: int = 1
    AGENT_TIMEOUT_SECONDS: int = 630  # 2× heartbeat_interval + 30s grace

    if SettingsConfigDict:
        model_config = SettingsConfigDict(
            env_file=(".env", "server/.env"),
            case_sensitive=True,
            extra="ignore",
        )
    else:

        class Config:
            env_file = (".env", "server/.env")
            case_sensitive = True


# Global settings instance (lazy loaded)
_settings: Settings | None = None


def get_settings() -> Settings:
    """Get or create Settings instance (singleton pattern)."""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
