from fastapi import APIRouter
from backend.app.schemas.common import ApiResponse
from backend.app.schemas.network import NetworkInterfacesData, NetworkSummaryData
from backend.app.services.network_service import NetworkService

router = APIRouter(prefix="/network", tags=["Network"])


@router.get("/interfaces", response_model=ApiResponse[NetworkInterfacesData])
async def get_network_interfaces() -> ApiResponse[NetworkInterfacesData]:
    """Retrieves available host network interfaces, IP addresses, MAC addresses, and status."""
    data = NetworkService.get_network_interfaces()
    return ApiResponse(
        success=True,
        message=f"Discovered {data.total_interfaces} network interface(s)",
        data=data,
    )


@router.get("/summary", response_model=ApiResponse[NetworkSummaryData])
async def get_network_summary() -> ApiResponse[NetworkSummaryData]:
    """Retrieves cumulative system-wide network throughput and packet transmission statistics."""
    data = NetworkService.get_network_summary()
    return ApiResponse(
        success=True,
        message="System network summary counters retrieved",
        data=data,
    )

