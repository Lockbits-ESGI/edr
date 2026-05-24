"""Server configuration loaded from environment and config file."""

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
    LOG_LEVEL: str = "INFO"
    CORS_ORIGINS: str = "*"  # comma-separated list of allowed origins, or "*" for all
    MAX_EVENTS_PER_PAGE: int = 100
    WORKERS: int = 1

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
