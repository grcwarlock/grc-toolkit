"""Assessment run and result endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    AssessmentTriggerRequest,
    AssessmentRunResponse,
    AssessmentResultResponse,
    AssessmentTrendResponse,
)
from db.repository import AssessmentRepository

router = APIRouter(prefix="/api/v1/assessments", tags=["assessments"])


@router.post("/run", response_model=AssessmentRunResponse, status_code=202)
async def trigger_assessment(
    request: AssessmentTriggerRequest, db: Session = Depends(get_db)
):
    """Trigger a compliance assessment run.

    Returns 202 Accepted — assessment runs asynchronously.
    """
    run = AssessmentRepository.create_run(
        db, framework=request.framework, triggered_by="api"
    )
    return AssessmentRunResponse(
        id=run.id,
        framework=run.framework,
        started_at=run.started_at,
        status=run.status,
    )


@router.get("/runs", response_model=list[AssessmentRunResponse])
async def list_runs(
    framework: str | None = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
):
    runs = AssessmentRepository.list_runs(db, framework=framework, limit=limit)
    return [
        AssessmentRunResponse(
            id=r.id, framework=r.framework, started_at=r.started_at,
            completed_at=r.completed_at, status=r.status,
            total_checks=r.total_checks, passed=r.passed,
            failed=r.failed, errors=r.errors, pass_rate=r.pass_rate,
            summary=r.summary,
        )
        for r in runs
    ]


@router.get("/runs/{run_id}", response_model=AssessmentRunResponse)
async def get_run(run_id: str, db: Session = Depends(get_db)):
    run = AssessmentRepository.get_run(db, run_id)
    if run is None:
        raise HTTPException(status_code=404, detail="Assessment run not found")
    return AssessmentRunResponse(
        id=run.id, framework=run.framework, started_at=run.started_at,
        completed_at=run.completed_at, status=run.status,
        total_checks=run.total_checks, passed=run.passed,
        failed=run.failed, errors=run.errors, pass_rate=run.pass_rate,
        summary=run.summary,
    )


@router.get("/runs/{run_id}/results", response_model=list[AssessmentResultResponse])
async def get_results(run_id: str, db: Session = Depends(get_db)):
    results = AssessmentRepository.get_results(db, run_id)
    return [
        AssessmentResultResponse(
            id=r.id, control_id=r.control_id, check_id=r.check_id,
            assertion=r.assertion, status=r.status, severity=r.severity,
            provider=r.provider, region=r.region, findings=r.findings,
            remediation=r.remediation, assessed_at=r.assessed_at,
        )
        for r in results
    ]


@router.get("/trend", response_model=AssessmentTrendResponse)
async def get_trend(
    framework: str = Query("nist_800_53"),
    last_n: int = Query(10, ge=1, le=50),
    db: Session = Depends(get_db),
):
    trend = AssessmentRepository.get_trend(db, framework=framework, last_n=last_n)
    return AssessmentTrendResponse(runs=trend)
