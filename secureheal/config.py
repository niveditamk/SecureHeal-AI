"""Application configuration loaded from environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Global settings — reads from .env or environment variables."""

    # LLM provider keys
    OPENAI_API_KEY: str = ""
    GOOGLE_API_KEY: str = ""
    MODEL_NAME: str = "gemini-2.0-flash"

    # Database
    DATABASE_URL: str = "postgresql+asyncpg://secureheal:secureheal@localhost:5432/secureheal"

    # Security tools
    SEMGREP_RULES: str = "auto"
    ZAP_API_URL: str = "http://localhost:8080"

    # Telemetry
    OTEL_EXPORTER_OTLP_ENDPOINT: str = "http://localhost:4317"

    # Application
    LOG_LEVEL: str = "INFO"
    MAX_RETRIES: int = 3
    PATCH_TIMEOUT_SECONDS: int = 300

    # API
    SECUREHEAL_API_URL: str = "http://localhost:8000"

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "extra": "ignore"}


settings = Settings()
