"""Shared utilities for cloud collectors."""

from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Callable

from modules.models import NormalizedEvidence

logger = logging.getLogger(__name__)


def create_evidence(
    control_id: str,
    check_id: str,
    provider: str,
    service: str,
    resource_type: str,
    region: str,
    account_id: str,
    data: dict,
    normalized_data: dict,
    status: str = "collected",
    error_message: str = "",
    metadata: dict | None = None,
) -> NormalizedEvidence:
    """Construct a NormalizedEvidence artifact with automatic hashing."""
    return NormalizedEvidence(
        control_id=control_id,
        check_id=check_id,
        provider=provider,
        service=service,
        resource_type=resource_type,
        region=region,
        account_id=account_id,
        data=data,
        normalized_data=normalized_data,
        status=status,
        error_message=error_message,
        metadata=metadata or {},
    )


def safe_collect(
    func: Callable,
    control_id: str,
    check_id: str,
    provider: str,
    service: str,
    region: str,
    account_id: str,
) -> NormalizedEvidence:
    """Wrap a collection call in error handling, returning error evidence on failure."""
    try:
        return func()
    except Exception as e:
        logger.error("Collection failed for %s/%s in %s: %s", service, check_id, region, e)
        return create_evidence(
            control_id=control_id,
            check_id=check_id,
            provider=provider,
            service=service,
            resource_type="",
            region=region,
            account_id=account_id,
            data={},
            normalized_data={},
            status="error",
            error_message=str(e),
        )


def compute_hash(data: dict) -> str:
    """SHA-256 hash of JSON-serialized data."""
    serialized = json.dumps(data, sort_keys=True, default=str).encode()
    return hashlib.sha256(serialized).hexdigest()
