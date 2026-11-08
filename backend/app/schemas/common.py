from datetime import datetime, timezone
from typing import Generic, Optional, TypeVar
from pydantic import BaseModel, Field

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Standardized API response wrapper."""

    success: bool = Field(True, description="Indicates whether the request was successful")
    message: Optional[str] = Field(None, description="Optional informational message")
    data: T = Field(description="Response payload")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the response",
    )


class ApiErrorDetail(BaseModel):
    """Detailed error structure for API exceptions."""

    code: str = Field(..., description="Machine-readable error code")
    detail: str = Field(..., description="Human-readable error description")


class ApiErrorResponse(BaseModel):
    """Standardized error response payload."""

    success: bool = Field(False, description="Always false for error responses")
    error: ApiErrorDetail = Field(..., description="Error detail object")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="UTC timestamp of the error",
    )

