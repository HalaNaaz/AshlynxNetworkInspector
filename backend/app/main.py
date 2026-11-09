from contextlib import asynccontextmanager
from typing import AsyncGenerator
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.analytics import router as analytics_router
from backend.app.api.capture import router as capture_router
from backend.app.api.discovery import router as discovery_router
from backend.app.api.health import router as health_router
from backend.app.api.network import router as network_router
from backend.app.api.reports import router as reports_router
from backend.app.api.scanner import router as scanner_router
from backend.app.api.security import router as security_router
from backend.app.api.traffic import router as traffic_router
from backend.app.core.config import settings
from backend.app.core.logging import logger
from backend.app.schemas.common import ApiErrorDetail, ApiErrorResponse


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """Lifespan event handler for startup and shutdown."""
    from pathlib import Path
    from backend.app.db.migrations import init_db
    from backend.app.db.session import get_db_connection
    from backend.app.db.repositories.reports_repo import ReportsRepository

    logger.info("Initializing %s v%s in %s mode", settings.app_name, settings.app_version, settings.app_env)
    logger.info("Server binding target: http://%s:%s", settings.host, settings.port)
    logger.info("Allowed CORS origins: %s", settings.cors_origins)

    # Initialize SQLite schema and run migrations
    conn = get_db_connection()
    init_db(conn)
    conn.close()

    # Self-healing ingestion of existing reports from disk
    reports_dir = Path(__file__).resolve().parent.parent.parent / "reports"
    if reports_dir.exists():
        synced = ReportsRepository.sync_from_disk(reports_dir)
        if synced > 0:
            logger.info("Self-healed %d report records from disk into SQLite registry", synced)

    yield
    logger.info("Shutting down %s...", settings.app_name)


app = FastAPI(
    title=settings.app_name,
    version=settings.app_version,
    description="Independent network security platform combining port scanning (Engine A) and live traffic analysis (Engine B).",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length"],
)


# Global Exception Handlers
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Handles request validation errors with consistent schema."""
    logger.warning("Validation error on %s %s: %s", request.method, request.url.path, exc.errors())
    error_response = ApiErrorResponse(
        success=False,
        error=ApiErrorDetail(
            code="VALIDATION_ERROR",
            detail=str(exc.errors()),
        ),
    )
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content=error_response.model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    """Handles unexpected server errors with structured response."""
    logger.error("Unhandled exception on %s %s: %s", request.method, request.url.path, str(exc), exc_info=True)
    error_response = ApiErrorResponse(
        success=False,
        error=ApiErrorDetail(
            code="INTERNAL_SERVER_ERROR",
            detail="An unexpected internal server error occurred.",
        ),
    )
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=error_response.model_dump(mode="json"),
    )


# Root endpoint
@app.get("/", tags=["Root"])
async def root():
    """Root info endpoint."""
    return {
        "name": settings.app_name,
        "abbreviation": settings.app_short_name,
        "version": settings.app_version,
        "status": "operational",
        "documentation": "/docs",
    }


# Include API routers under /api
app.include_router(health_router, prefix="/api")
app.include_router(network_router, prefix="/api")
app.include_router(scanner_router, prefix="/api")
app.include_router(discovery_router, prefix="/api")
app.include_router(capture_router, prefix="/api")
app.include_router(analytics_router, prefix="/api")
app.include_router(security_router, prefix="/api")
app.include_router(traffic_router, prefix="/api")
app.include_router(reports_router, prefix="/api")

