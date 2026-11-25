"""SENTINELX FastAPI application entry point."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from . import __version__
from .api import api_router
from .config import FRONTEND_DIST_DIR, STATIC_DIR, settings
from .database import SessionLocal, init_db
from .security import role_from_request
from .services.seed import seed_database


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    if settings.seed_demo_data:
        db = SessionLocal()
        try:
            seed_database(db)
        finally:
            db.close()
    yield


app = FastAPI(
    title="SENTINELX - Agentic AI SOC Analyst",
    description=(
        "Agentic AI-powered Security Operations Center: log collection, detection, "
        "correlation, multi-agent investigation, human-approved response and reporting."
    ),
    version=__version__,
    lifespan=lifespan,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    # Swagger/ReDoc load their assets from public CDNs. Keep the strict policy
    # for the application itself, but exempt the interactive API docs pages.
    if request.url.path not in {"/api/docs", "/api/redoc"}:
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
            "connect-src 'self'; font-src 'self' data:"
        )
    return response


@app.middleware("http")
async def viewer_write_guard(request: Request, call_next):
    """Security Viewer is read-only across the whole API, including legacy routes."""
    if (
        request.method in {"POST", "PUT", "PATCH", "DELETE"}
        and request.url.path.startswith("/api/")
        and request.url.path != "/api/auth/login"
        and role_from_request(request) == "viewer"
    ):
        return JSONResponse({"detail": "Security Viewer role is read-only"}, status_code=403)
    return await call_next(request)


app.include_router(api_router)

# The React SPA is the primary dashboard when built. The original zero-build
# dashboard remains available under /static and is used when dist/ is absent.
if FRONTEND_DIST_DIR.is_dir():
    assets_dir = FRONTEND_DIST_DIR / "assets"
    if assets_dir.is_dir():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="assets")
if STATIC_DIR.is_dir():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")


@app.get("/health", include_in_schema=False)
def health_alias() -> JSONResponse:
    return JSONResponse({"status": "ok", "version": __version__})


if FRONTEND_DIST_DIR.is_dir():
    @app.get("/{spa_path:path}", include_in_schema=False)
    def spa_index(spa_path: str) -> FileResponse:
        """Serve the React app for all non-API client-side routes."""
        return FileResponse(str(FRONTEND_DIST_DIR / "index.html"))


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    if FRONTEND_DIST_DIR.is_dir():
        return FileResponse(str(FRONTEND_DIST_DIR / "index.html"))
    return FileResponse(str(STATIC_DIR / "index.html"))
