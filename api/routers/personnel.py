"""Personnel & training management endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    PersonnelCreate,
    PersonnelDashboardResponse,
    PersonnelResponse,
    PersonnelUpdate,
    TrainingRecordCreate,
)
from api.security import require_api_key
from db.repository import PersonnelRepository

router = APIRouter(prefix="/api/v1/personnel", tags=["personnel"])


def _to_response(p) -> PersonnelResponse:
    return PersonnelResponse(
        id=p.id, full_name=p.full_name, email=p.email,
        department=p.department, role=p.role, title=p.title,
        manager=p.manager, start_date=p.start_date,
        termination_date=p.termination_date, is_active=p.is_active,
        background_check_date=p.background_check_date,
        background_check_status=p.background_check_status,
        last_access_review=p.last_access_review,
        access_review_status=p.access_review_status,
        training_records=p.training_records or [],
        system_access=p.system_access or [],
        control_mappings=p.control_mappings or [],
        created_at=p.created_at,
    )


@router.post("/", response_model=PersonnelResponse, status_code=201)
async def create_personnel(
    request: PersonnelCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    person = PersonnelRepository.create(db, **request.model_dump())
    return _to_response(person)


@router.get("/", response_model=list[PersonnelResponse])
async def list_personnel(
    active_only: bool = Query(True),
    department: str | None = Query(None),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    personnel = PersonnelRepository.list_personnel(db, active_only=active_only, department=department)
    return [_to_response(p) for p in personnel]


@router.get("/dashboard", response_model=PersonnelDashboardResponse)
async def personnel_dashboard(
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    return PersonnelRepository.get_dashboard(db)


@router.get("/{pid}", response_model=PersonnelResponse)
async def get_personnel(
    pid: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    p = PersonnelRepository.get(db, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Personnel not found")
    return _to_response(p)


@router.put("/{pid}", response_model=PersonnelResponse)
async def update_personnel(
    pid: str,
    request: PersonnelUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    updates = request.model_dump(exclude_none=True)
    try:
        p = PersonnelRepository.update(db, pid, updates)
    except ValueError:
        raise HTTPException(status_code=404, detail="Personnel not found")
    return _to_response(p)


@router.post("/{pid}/training", response_model=PersonnelResponse)
async def add_training_record(
    pid: str,
    request: TrainingRecordCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    p = PersonnelRepository.get(db, pid)
    if p is None:
        raise HTTPException(status_code=404, detail="Personnel not found")
    records = list(p.training_records or [])
    records.append({
        **request.model_dump(mode="json"),
        "recorded_at": datetime.now(UTC).isoformat(),
    })
    PersonnelRepository.update(db, pid, {"training_records": records})
    p = PersonnelRepository.get(db, pid)
    return _to_response(p)


@router.post("/{pid}/access-review", response_model=PersonnelResponse)
async def complete_access_review(
    pid: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Mark access review as completed for this person."""
    try:
        p = PersonnelRepository.update(db, pid, {
            "last_access_review": datetime.now(UTC).date(),
            "access_review_status": "completed",
        })
    except ValueError:
        raise HTTPException(status_code=404, detail="Personnel not found")
    return _to_response(p)
