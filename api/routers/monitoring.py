"""Continuous monitoring & drift detection endpoints."""

from __future__ import annotations

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    DriftAlertResponse,
    MonitoringScheduleCreate,
    MonitoringScheduleResponse,
    MonitoringScheduleUpdate,
)
from api.security import require_api_key
from db.repository import AssessmentRepository, MonitoringRepository

router = APIRouter(prefix="/api/v1/monitoring", tags=["monitoring"])


def _to_response(s) -> MonitoringScheduleResponse:
    return MonitoringScheduleResponse(
        id=s.id, name=s.name, framework=s.framework, cadence=s.cadence,
        providers=s.providers or [], is_active=s.is_active,
        last_run_at=s.last_run_at, last_run_id=s.last_run_id,
        last_pass_rate=s.last_pass_rate, drift_detected=s.drift_detected,
        drift_details=s.drift_details, alert_on_drift=s.alert_on_drift,
        alert_channels=s.alert_channels or [], created_at=s.created_at,
    )


@router.post("/schedules", response_model=MonitoringScheduleResponse, status_code=201)
async def create_schedule(
    request: MonitoringScheduleCreate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    schedule = MonitoringRepository.create_schedule(db, **request.model_dump())
    return _to_response(schedule)


@router.get("/schedules", response_model=list[MonitoringScheduleResponse])
async def list_schedules(
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    schedules = MonitoringRepository.list_schedules(db, active_only=False)
    return [_to_response(s) for s in schedules]


@router.get("/schedules/{schedule_id}", response_model=MonitoringScheduleResponse)
async def get_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    s = MonitoringRepository.get_schedule(db, schedule_id)
    if s is None:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_response(s)


@router.put("/schedules/{schedule_id}", response_model=MonitoringScheduleResponse)
async def update_schedule(
    schedule_id: str,
    request: MonitoringScheduleUpdate,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    updates = request.model_dump(exclude_none=True)
    try:
        s = MonitoringRepository.update_schedule(db, schedule_id, updates)
    except ValueError:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return _to_response(s)


@router.post("/schedules/{schedule_id}/run", response_model=DriftAlertResponse)
async def trigger_monitoring_run(
    schedule_id: str,
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Trigger an immediate monitoring run and check for drift."""
    schedule = MonitoringRepository.get_schedule(db, schedule_id)
    if schedule is None:
        raise HTTPException(status_code=404, detail="Schedule not found")

    previous_pass_rate = schedule.last_pass_rate

    # Simulate a monitoring run by checking latest assessment
    runs = AssessmentRepository.list_runs(db, framework=schedule.framework, limit=2)
    current_pass_rate = runs[0].pass_rate if runs else None

    # Detect drift
    degraded = []
    new_failures = []
    drift = False

    if previous_pass_rate is not None and current_pass_rate is not None:
        if current_pass_rate < previous_pass_rate:
            drift = True
            degraded.append({
                "metric": "pass_rate",
                "previous": previous_pass_rate,
                "current": current_pass_rate,
                "delta": round(current_pass_rate - previous_pass_rate, 2),
            })

    if runs and len(runs) >= 2:
        current_results = AssessmentRepository.get_results(db, runs[0].id)
        previous_results = AssessmentRepository.get_results(db, runs[1].id)
        prev_failed = {r.control_id for r in previous_results if r.status == "fail"}
        curr_failed = {r.control_id for r in current_results if r.status == "fail"}
        newly_failed = curr_failed - prev_failed
        for cid in list(newly_failed)[:10]:
            drift = True
            new_failures.append({"control_id": cid, "status": "newly_failed"})

    # Update schedule
    MonitoringRepository.update_schedule(db, schedule_id, {
        "last_run_at": datetime.now(UTC),
        "last_run_id": runs[0].id if runs else None,
        "last_pass_rate": current_pass_rate,
        "drift_detected": drift,
        "drift_details": {"degraded": degraded, "new_failures": new_failures} if drift else None,
    })

    return DriftAlertResponse(
        schedule_id=schedule_id,
        framework=schedule.framework,
        drift_detected=drift,
        previous_pass_rate=previous_pass_rate,
        current_pass_rate=current_pass_rate,
        degraded_controls=degraded,
        new_failures=new_failures,
        timestamp=datetime.now(UTC),
    )


@router.get("/due", response_model=list[MonitoringScheduleResponse])
async def get_due_schedules(
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    """Get schedules that are due for their next monitoring run."""
    schedules = MonitoringRepository.get_due_schedules(db)
    return [_to_response(s) for s in schedules]
