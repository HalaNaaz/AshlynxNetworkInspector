from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from fastapi.responses import FileResponse

from backend.app.core.logging import logger
from backend.app.reports.report_manager import ReportManager
from backend.app.schemas.common import ApiResponse
from backend.app.schemas.reports import (
    ReportGenerateRequest,
    ReportMetadataItem,
    ReportPreviewResponse,
    ReportSourcesResponse,
)

router = APIRouter(prefix="/reports", tags=["Reports & Analytics"])


@router.get("/sources", response_model=ApiResponse[ReportSourcesResponse])
async def list_report_sources():
    """Lists all available telemetry and scan data sources across active and past sessions."""
    try:
        sources = ReportManager.list_sources()
        return ApiResponse(
            success=True,
            message="Retrieved available report data sources.",
            data=ReportSourcesResponse(sources=sources),
        )
    except Exception as exc:
        logger.error("Failed to list report sources: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to query active report sources.",
        )


@router.post("/generate", response_model=ApiResponse[ReportMetadataItem], status_code=status.HTTP_201_CREATED)
async def generate_report(request: ReportGenerateRequest):
    """Generates an executive security audit report in PDF, CSV, or JSON format."""
    try:
        meta = ReportManager.generate_report(request)
        return ApiResponse(
            success=True,
            message=f"Successfully generated {request.report_format.value.upper()} report.",
            data=meta,
        )
    except ValueError as exc:
        logger.warning("Invalid report generation parameters: %s", exc)
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Report generation failure: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Report generation failed: {exc}",
        )


@router.get("/history", response_model=ApiResponse[List[ReportMetadataItem]])
async def list_report_history(limit: int = Query(50, ge=1, le=100)):
    """Retrieves metadata for generated reports in reverse chronological order."""
    try:
        history = ReportManager.list_history(limit=limit)
        return ApiResponse(
            success=True,
            message=f"Retrieved {len(history)} report entries.",
            data=history,
        )
    except Exception as exc:
        logger.error("Failed to retrieve report history: %s", exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to retrieve report history.",
        )


@router.get("/{report_id}/preview", response_model=ApiResponse[ReportPreviewResponse])
async def preview_report(report_id: str):
    """Returns preview metadata, KPI summary, and top findings for visual inspection."""
    try:
        preview = ReportManager.get_preview(report_id)
        return ApiResponse(
            success=True,
            message="Report preview generated successfully.",
            data=preview,
        )
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found.")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Preview retrieval failed for %s: %s", report_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to generate report preview.",
        )


@router.get("/{report_id}/download")
async def download_report(report_id: str):
    """Streams the generated document file with attachment download headers."""
    try:
        file_path, mime_type, filename = ReportManager.get_report_file(report_id)
        return FileResponse(
            path=str(file_path),
            media_type=mime_type,
            filename=filename,
            content_disposition_type="attachment",
        )
    except FileNotFoundError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report file '{report_id}' not found.")
    except PermissionError:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied.")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Download error for report %s: %s", report_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to stream report file.",
        )


@router.delete("/{report_id}", response_model=ApiResponse[bool])
async def delete_report(report_id: str):
    """Safely removes a generated report file and its metadata index."""
    try:
        success = ReportManager.delete_report(report_id)
        if not success:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Report '{report_id}' not found.")
        return ApiResponse(
            success=True,
            message=f"Report '{report_id}' deleted successfully.",
            data=True,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc))
    except Exception as exc:
        logger.error("Deletion error for report %s: %s", report_id, exc, exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to delete report.",
        )

