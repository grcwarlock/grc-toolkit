"""Evidence collection and retrieval endpoints."""

from __future__ import annotations

import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    CollectionRequest,
    CollectionResponse,
    EvidenceListResponse,
    EvidenceResponse,
    EvidenceVerifyResponse,
)
from db.repository import EvidenceRepository

router = APIRouter(prefix="/api/v1/evidence", tags=["evidence"])


@router.post("/collect", response_model=CollectionResponse, status_code=202)
async def trigger_collection(request: CollectionRequest, db: Session = Depends(get_db)):
    """Trigger evidence collection from cloud providers.

    Returns 202 Accepted — collection runs asynchronously.
    In production this would be dispatched to a Celery task queue.
    """
    run_id = str(uuid.uuid4())
    return CollectionResponse(
        run_id=run_id,
        status="pending",
        artifacts_collected=0,
        started_at=datetime.now(UTC),
    )


@router.get("/", response_model=EvidenceListResponse)
async def list_evidence(
    run_id: str | None = Query(None),
    control_id: str | None = Query(None),
    provider: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    offset = (page - 1) * page_size
    records = EvidenceRepository.list_evidence(
        db, run_id=run_id, control_id=control_id, provider=provider,
        limit=page_size, offset=offset,
    )
    total = EvidenceRepository.count_evidence(
        db, run_id=run_id, control_id=control_id, provider=provider,
    )
    return EvidenceListResponse(
        items=[
            EvidenceResponse(
                id=r.id, control_id=r.control_id, check_id=r.check_id,
                provider=r.provider, service=r.service,
                resource_type=r.resource_type, region=r.region,
                account_id=r.account_id, collected_at=r.collected_at,
                status=r.status, sha256_hash=r.sha256_hash,
                normalized_data=r.normalized_data,
            )
            for r in records
        ],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.get("/{evidence_id}", response_model=EvidenceResponse)
async def get_evidence(evidence_id: str, db: Session = Depends(get_db)):
    record = EvidenceRepository.get_evidence(db, evidence_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence not found")
    return EvidenceResponse(
        id=record.id, control_id=record.control_id, check_id=record.check_id,
        provider=record.provider, service=record.service,
        resource_type=record.resource_type, region=record.region,
        account_id=record.account_id, collected_at=record.collected_at,
        status=record.status, sha256_hash=record.sha256_hash,
        normalized_data=record.normalized_data,
    )


@router.get("/{evidence_id}/verify", response_model=EvidenceVerifyResponse)
async def verify_evidence(evidence_id: str, db: Session = Depends(get_db)):
    """Verify evidence integrity by recomputing SHA-256 hash."""
    import hashlib
    import json

    record = EvidenceRepository.get_evidence(db, evidence_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Evidence not found")

    computed = hashlib.sha256(
        json.dumps(record.data, sort_keys=True, default=str).encode()
    ).hexdigest()

    return EvidenceVerifyResponse(
        evidence_id=record.id,
        integrity_valid=(computed == record.sha256_hash),
        stored_hash=record.sha256_hash,
        computed_hash=computed,
    )
