import platform
from fastapi import APIRouter
from backend.app.core.config import settings
from backend.app.schemas.common import ApiResponse
from backend.app.schemas.health import HealthData

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", response_model=ApiResponse[HealthData])
async def get_health() -> ApiResponse[HealthData]:
    """Health check endpoint returning system, runtime, and application status."""
    os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"
    health_data = HealthData(
        application_name=settings.app_name,
        version=settings.app_version,
        backend_status="operational",
        operating_system=os_info,
        python_version=platform.python_version(),
    )
    return ApiResponse(
        success=True,
        message="Backend operational",
        data=health_data,
    )

