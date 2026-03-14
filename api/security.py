"""
Security middleware and utilities for the GRC Toolkit API.

Provides API key authentication, rate limiting, security headers,
audit logging, and input sanitization.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import time
import uuid
from collections import defaultdict
from collections.abc import Callable
from datetime import UTC, datetime

from fastapi import Depends, HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ── API Key Authentication ────────────────────────────────────────────

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Valid API keys loaded from environment variable (comma-separated)
# Example: GRC_API_KEYS="key1,key2,key3"
_api_keys_cache: set[str] | None = None


def _get_valid_api_keys() -> set[str]:
    """Load valid API keys from environment. Cached after first call."""
    global _api_keys_cache
    if _api_keys_cache is not None:
        return _api_keys_cache

    raw = os.environ.get("GRC_API_KEYS", "")
    if raw:
        _api_keys_cache = {k.strip() for k in raw.split(",") if k.strip()}
    else:
        _api_keys_cache = set()
    return _api_keys_cache


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode(), b.encode())


async def require_api_key(
    request: Request,
    api_key: str | None = Security(API_KEY_HEADER),
) -> str:
    """Dependency that enforces API key authentication.

    Skips auth if GRC_API_KEYS is not set (development mode).
    """
    valid_keys = _get_valid_api_keys()

    # Development mode: no keys configured, allow all requests
    if not valid_keys:
        return "anonymous"

    if api_key is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing API key. Provide X-API-Key header.",
        )

    for valid_key in valid_keys:
        if _constant_time_compare(api_key, valid_key):
            return api_key

    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Invalid API key.",
    )


# ── Rate Limiting Middleware ──────────────────────────────────────────

class RateLimitMiddleware(BaseHTTPMiddleware):
    """Token bucket rate limiter per client IP.

    Configurable via environment variables:
    - GRC_RATE_LIMIT_RPM: requests per minute (default: 120)
    - GRC_RATE_LIMIT_BURST: burst size (default: 20)
    """

    def __init__(self, app, rpm: int | None = None, burst: int | None = None):
        super().__init__(app)
        self.rpm = rpm or int(os.environ.get("GRC_RATE_LIMIT_RPM", "120"))
        self.burst = burst or int(os.environ.get("GRC_RATE_LIMIT_BURST", "20"))
        self.tokens: dict[str, float] = defaultdict(lambda: float(self.burst))
        self.last_refill: dict[str, float] = defaultdict(time.monotonic)

    def _get_client_ip(self, request: Request) -> str:
        forwarded = request.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Skip rate limiting for health check
        if request.url.path == "/health":
            return await call_next(request)

        client_ip = self._get_client_ip(request)
        now = time.monotonic()

        # Refill tokens
        elapsed = now - self.last_refill[client_ip]
        self.tokens[client_ip] = min(
            self.burst,
            self.tokens[client_ip] + elapsed * (self.rpm / 60.0),
        )
        self.last_refill[client_ip] = now

        if self.tokens[client_ip] < 1:
            return Response(
                content='{"detail":"Rate limit exceeded. Try again later."}',
                status_code=429,
                media_type="application/json",
                headers={"Retry-After": str(int(60 / self.rpm))},
            )

        self.tokens[client_ip] -= 1
        response = await call_next(request)

        # Add rate limit headers
        response.headers["X-RateLimit-Limit"] = str(self.rpm)
        response.headers["X-RateLimit-Remaining"] = str(int(self.tokens[client_ip]))
        return response


# ── Security Headers Middleware ───────────────────────────────────────

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add OWASP-recommended security headers to all responses."""

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
        response.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"

        # HSTS only when behind TLS (Replit, production)
        if request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains"
            )

        return response


# ── Audit Logging Middleware ──────────────────────────────────────────

class AuditLogMiddleware(BaseHTTPMiddleware):
    """Log all API requests for compliance audit trail.

    Writes structured log entries with request metadata.
    Sensitive headers (Authorization, API keys) are redacted.
    """

    REDACTED_HEADERS = {"authorization", "x-api-key", "cookie"}

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        request_id = str(uuid.uuid4())
        start_time = time.monotonic()

        # Attach request ID for downstream correlation
        request.state.request_id = request_id

        # Extract client info
        client_ip = request.headers.get(
            "X-Forwarded-For", request.client.host if request.client else "unknown"
        )
        if "," in client_ip:
            client_ip = client_ip.split(",")[0].strip()

        response = await call_next(request)

        duration_ms = (time.monotonic() - start_time) * 1000

        # Build audit entry
        audit_entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "request_id": request_id,
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else "",
            "client_ip": client_ip,
            "user_agent": request.headers.get("User-Agent", ""),
            "status_code": response.status_code,
            "duration_ms": round(duration_ms, 2),
        }

        # Log level based on status code
        if response.status_code >= 500:
            logger.error("AUDIT %s", audit_entry)
        elif response.status_code >= 400:
            logger.warning("AUDIT %s", audit_entry)
        else:
            logger.info("AUDIT %s", audit_entry)

        # Add request ID to response for traceability
        response.headers["X-Request-Id"] = request_id
        return response


# ── Input Sanitization Helpers ────────────────────────────────────────

# Allowed values for enum-like fields
VALID_PROVIDERS = {"aws", "azure", "gcp"}
VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_STATUSES = {"collected", "pass", "fail", "error", "not_assessed"}
VALID_CRITICALITIES = {"Critical", "High", "Medium", "Low"}
VALID_DATA_CLASSIFICATIONS = {"Restricted", "Confidential", "Internal", "Public"}
VALID_VENDOR_CATEGORIES = {
    "SaaS", "IaaS", "PaaS", "Consulting", "Hardware", "Other",
}

VENDOR_UPDATABLE_FIELDS = frozenset({
    "name", "category", "criticality", "data_classification",
    "contract_end", "certifications", "risk_score", "risk_level",
    "last_assessment_date", "notes",
})


def validate_enum(value: str, allowed: set[str], field_name: str) -> str:
    """Validate that a value is in a set of allowed values."""
    if value not in allowed:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Invalid {field_name}: '{value}'. Must be one of: {sorted(allowed)}",
        )
    return value
