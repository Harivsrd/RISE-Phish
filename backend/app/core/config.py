"""Configuration management for RISE-Phish using pydantic-settings.
"""
from functools import lru_cache
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field


class Settings(BaseSettings):
    # Application settings
    APP_NAME: str = "RISE-Phish API"
    APP_ENV: str = "development"
    DEBUG: bool = True
    HOST: str = "127.0.0.1"
    PORT: int = 8000
    API_V1_PREFIX: str = "/api/v1"

    # CORS configuration
    CORS_ORIGINS: List[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    # Crawler settings
    HEADLESS_BROWSER: bool = True
    CRAWLER_TIMEOUT_MS: int = 30000
    SCREENSHOTS_DIR: str = "./temp/screenshots"

    # OCR settings
    OCR_ENGINE: str = "tesseract"
    TESSERACT_CMD: str = ""

    # SLM settings
    SLM_BACKEND: str = "mock"
    SLM_MODEL_NAME: str = "microsoft/Phi-3-mini-4k-instruct"
    SLM_API_KEY: str = ""
    SLM_API_URL: str = ""

    # Storage settings
    SQLITE_DB_URL: str = "sqlite:///./rise_phish.db"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache()
def get_settings() -> Settings:
    """Provides a cached singleton instance of Settings."""
    return Settings()
