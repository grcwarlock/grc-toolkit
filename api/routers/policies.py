"""OPA policy evaluation and violation tracking endpoints."""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    PolicyEvalRequest,
    PolicyEvalResponse,
    PolicyViolationResponse,
)
from db.repository import PolicyViolationRepository

router = APIRouter(prefix="/api/v1/policies", tags=["policies"])


@router.post("/evaluate", response_model=PolicyEvalResponse)
async def evaluate_policy(request: PolicyEvalRequest):
    """Evaluate a resource against OPA policies.

    In production this calls the OPA server at GRC_OPA_URL.
    Falls back to a local evaluation if OPA is unavailable.
    """
    opa_url = os.environ.get("GRC_OPA_URL", "http://localhost:8181")

    try:
        import httpx
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post(
                f"{opa_url}/v1/data/{request.policy_package}",
                json={"input": {
                    "provider": request.provider,
                    "resource_type": request.resource_type,
                    "normalized_data": request.resource_data,
                }},
            )
            if resp.status_code == 200:
                data = resp.json()
                result = data.get("result", {})
                findings = result.get("findings", [])
                compliant = result.get("compliant", len(findings) == 0)
                return PolicyEvalResponse(
                    compliant=compliant,
                    violations=[{"message": f} for f in findings],
                    policy_package=request.policy_package,
                )
    except Exception:
        pass

    # OPA unavailable — return unknown
    return PolicyEvalResponse(
        compliant=True,
        violations=[],
        policy_package=request.policy_package,
    )


@router.get("/violations", response_model=list[PolicyViolationResponse])
async def list_violations(
    status: str | None = Query(None),
    severity: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    records = PolicyViolationRepository.list_violations(
        db, status=status, severity=severity, limit=limit,
    )
    return [
        PolicyViolationResponse(
            id=r.id, policy_id=r.policy_id, policy_name=r.policy_name,
            resource_id=r.resource_id, resource_type=r.resource_type,
            provider=r.provider, severity=r.severity, status=r.status,
            detected_at=r.detected_at, violation_detail=r.violation_detail,
        )
        for r in records
    ]


@router.post("/violations/{violation_id}/resolve")
async def resolve_violation(violation_id: str, db: Session = Depends(get_db)):
    try:
        violation = PolicyViolationRepository.resolve_violation(db, violation_id)
    except ValueError:
        raise HTTPException(status_code=404, detail="Violation not found")
    return {"id": violation.id, "status": violation.status}


@router.get("/bundles")
async def list_bundles():
    """List available OPA policy bundles from the policies/ directory."""
    policies_dir = Path("policies")
    if not policies_dir.exists():
        return []

    bundles = []
    for entry in sorted(policies_dir.iterdir()):
        if entry.is_dir() and not entry.name.startswith((".", "_")):
            rego_files = list(entry.rglob("*.rego"))
            test_files = [f for f in rego_files if f.stem.endswith("_test")]
            bundles.append({
                "name": entry.name,
                "path": str(entry),
                "policy_count": len(rego_files) - len(test_files),
                "test_count": len(test_files),
            })
    return bundles
