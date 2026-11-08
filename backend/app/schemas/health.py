from pydantic import BaseModel, Field


class HealthData(BaseModel):
    """System health data payload."""

    application_name: str = Field(..., description="Application name")
    version: str = Field(..., description="Application version")
    backend_status: str = Field(..., description="Operational status of backend")
    operating_system: str = Field(..., description="Host operating system")
    python_version: str = Field(..., description="Python runtime version")

