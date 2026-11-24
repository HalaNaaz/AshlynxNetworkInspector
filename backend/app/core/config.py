from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict
from typing import List, Union


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

    # API Authentication (VULN-001)
    api_token: str | None = None
    api_auth_enabled: bool = True

    # CORS configuration - restricted to local frontend (VULN-004)
    cors_origins: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ]
    cors_allow_methods: List[str] = [
        "GET",
        "POST",
        "PATCH",
        "DELETE",
        "OPTIONS",
    ]
    cors_allow_headers: List[str] = [
        "Content-Type",
        "Authorization",
        "Accept",
        "X-Requested-With",
        "Origin",
    ]
    cors_expose_headers: List[str] = [
        "Content-Disposition",
        "Content-Type",
        "Content-Length",
    ]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def validate_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            v = [origin.strip() for origin in v.split(",") if origin.strip()]
        if "*" in v:
            raise ValueError(
                "Wildcard '*' origin is forbidden when allow_credentials=True in ANI"
            )
        return v

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
