"""
GRC Toolkit API — FastAPI application.

Provides REST endpoints for evidence collection, control assessment,
risk analysis, framework management, vendor risk, and policy evaluation.
"""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routers import (
    ai_reasoning,
    assessments,
    audit_collab,
    auth,
    dashboard,
    data_silos,
    evidence,
    exports,
    frameworks,
    integrations,
    monitoring,
    personnel,
    policies,
    questionnaires,
    risk,
    settings,
    ssp,
    tasks,
    tool_config,
    trust,
    vendors,
)
from api.security import (
    AuditLogMiddleware,
    RateLimitMiddleware,
    SecurityHeadersMiddleware,
)
from db.session import init_db

logger = logging.getLogger(__name__)

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"

# CORS origins: configure via GRC_CORS_ORIGINS env var (comma-separated).
# Use "*" for development or Replit where the origin is dynamic.
_default_origins = "*"
CORS_ORIGINS = [
    o.strip()
    for o in os.environ.get("GRC_CORS_ORIGINS", _default_origins).split(",")
    if o.strip()
]


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on startup."""
    init_db()
    logger.info("GRC Toolkit API started — database initialized")
    yield


app = FastAPI(
    title="GRC Toolkit API",
    description="Governance, Risk, and Compliance automation platform",
    version="0.4.0",
    lifespan=lifespan,
    docs_url="/docs" if os.environ.get("GRC_ENABLE_DOCS", "true") == "true" else None,
    redoc_url=None,
)

# ── Middleware (order matters: last added = first executed) ───────────

# CORS — explicit origin whitelist, no wildcard with credentials
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["X-API-Key", "Content-Type", "Accept", "Authorization"],
)

# Security headers (HSTS, X-Frame-Options, etc.)
app.add_middleware(SecurityHeadersMiddleware)

# Audit logging for all requests
app.add_middleware(AuditLogMiddleware)

# Rate limiting (configurable via GRC_RATE_LIMIT_RPM / GRC_RATE_LIMIT_BURST)
app.add_middleware(RateLimitMiddleware)

# ── Routers ──────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(dashboard.router)
app.include_router(tool_config.router)
app.include_router(integrations.router)
app.include_router(evidence.router)
app.include_router(assessments.router)
app.include_router(risk.router)
app.include_router(frameworks.router)
app.include_router(vendors.router)
app.include_router(policies.router)
app.include_router(exports.router)
app.include_router(data_silos.router)
app.include_router(trust.router)
app.include_router(settings.router)
app.include_router(monitoring.router)
app.include_router(questionnaires.router)
app.include_router(tasks.router)
app.include_router(personnel.router)
app.include_router(audit_collab.router)
app.include_router(ssp.router)
app.include_router(ai_reasoning.router)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": app.version,
        "timestamp": datetime.now(UTC).isoformat(),
    }


# Serve frontend static files (SPA with client-side routing)
if STATIC_DIR.exists():
    if (STATIC_DIR / "assets").exists():
        app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets")), name="assets")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(str(STATIC_DIR / "index.html"))

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        file_path = STATIC_DIR / full_path
        if file_path.exists() and file_path.is_file():
            return FileResponse(str(file_path))
        return FileResponse(str(STATIC_DIR / "index.html"))
