from typing import List
from pydantic import BaseModel, Field


class TrafficStatusData(BaseModel):
    """Traffic analyzer engine status and capabilities."""

    available: bool = Field(..., description="Whether packet capture engine is active and available")
    status: str = Field(..., description="Engine operational status code")
    message: str = Field(..., description="Human-readable status summary")
    engine_version: str = Field(..., description="Traffic engine version")
    supported_protocols: List[str] = Field(..., description="Protocols recognized by analyzer")
    live_capture_ready: bool = Field(..., description="Whether live capture pipeline is ready to attach")
    payload_storage_enabled: bool = Field(..., description="False by default to respect privacy/security")

