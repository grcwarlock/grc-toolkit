"""
GRC Toolkit API — FastAPI application.

Provides REST endpoints for evidence collection, control assessment,
risk analysis, framework management, vendor risk, and policy evaluation.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime

from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from api.routers import assessments, evidence, frameworks, policies, risk, vendors
from db.session import init_db

STATIC_DIR = Path(__file__).resolve().parent.parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialize database tables on startup."""
    init_db()
    yield


app = FastAPI(
    title="GRC Toolkit API",
    description="Governance, Risk, and Compliance automation platform",
    version="0.2.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(evidence.router)
app.include_router(assessments.router)
app.include_router(risk.router)
app.include_router(frameworks.router)
app.include_router(vendors.router)
app.include_router(policies.router)


@app.get("/health")
async def health():
    return {
        "status": "healthy",
        "version": "0.2.0",
        "timestamp": datetime.now(UTC).isoformat(),
    }


# Serve frontend static files
if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    @app.get("/")
    async def serve_frontend():
        return FileResponse(str(STATIC_DIR / "index.html"))
