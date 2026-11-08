from fastapi import APIRouter
from backend.app.schemas.common import ApiResponse
from backend.app.schemas.traffic import TrafficStatusData
from backend.app.services.network_service import NetworkService

router = APIRouter(prefix="/traffic", tags=["Traffic Analyzer"])


@router.get("/status", response_model=ApiResponse[TrafficStatusData])
async def get_traffic_status() -> ApiResponse[TrafficStatusData]:
    """Returns live packet capture engine status, supported protocols, and availability."""
    data = NetworkService.get_traffic_status()
    return ApiResponse(
        success=True,
        message=data.message,
        data=data,
    )

