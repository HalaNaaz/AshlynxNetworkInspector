from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List


class Settings(BaseSettings):
    """Application settings for Ashlynx Network Inspector."""

    app_name: str = "Ashlynx Network Inspector"
    app_short_name: str = "ANI"
    app_version: str = "1.0.0"
    app_env: str = "development"
    debug: bool = False

    # Server configuration - bound to localhost for security
    host: str = "127.0.0.1"
    port: int = 8000

    # CORS configuration - restricted to local frontend
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]

    # Authorized scan targets restriction
    allowed_scan_networks: List[str] = [
        "127.0.0.1/32",
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
    ]

    # Log level
    log_level: str = "INFO"

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ANI_",
        extra="ignore"
    )


settings = Settings()

