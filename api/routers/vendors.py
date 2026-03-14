"""Vendor risk management endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from api.deps import get_db
from api.schemas import (
    VendorCreate,
    VendorDashboardResponse,
    VendorResponse,
    VendorUpdate,
)
from api.security import (
    VALID_CRITICALITIES,
    VALID_DATA_CLASSIFICATIONS,
    VALID_VENDOR_CATEGORIES,
    VENDOR_UPDATABLE_FIELDS,
    require_api_key,
    validate_enum,
)
from db.repository import VendorRepository

router = APIRouter(prefix="/api/v1/vendors", tags=["vendors"])


def _vendor_to_response(v) -> VendorResponse:
    return VendorResponse(
        id=v.id, name=v.name, category=v.category,
        criticality=v.criticality, data_classification=v.data_classification,
        contract_start=v.contract_start, contract_end=v.contract_end,
        last_assessment_date=v.last_assessment_date,
        certifications=v.certifications or [],
        risk_score=v.risk_score, risk_level=v.risk_level,
        is_active=v.is_active,
    )


@router.post("/", response_model=VendorResponse, status_code=201)
async def create_vendor(request: VendorCreate, db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    # Validate enum fields
    validate_enum(request.criticality, VALID_CRITICALITIES, "criticality")
    validate_enum(request.data_classification, VALID_DATA_CLASSIFICATIONS, "data_classification")
    validate_enum(request.category, VALID_VENDOR_CATEGORIES, "category")
    # Validate contract dates
    if request.contract_end < request.contract_start:
        raise HTTPException(
            status_code=422,
            detail="contract_end must be >= contract_start",
        )
    vendor = VendorRepository.create_vendor(db, **request.model_dump())
    return _vendor_to_response(vendor)


@router.get("/", response_model=list[VendorResponse])
async def list_vendors(
    active_only: bool = Query(True),
    db: Session = Depends(get_db),
    api_key: str = Depends(require_api_key),
):
    vendors = VendorRepository.list_vendors(db, active_only=active_only)
    return [_vendor_to_response(v) for v in vendors]


@router.get("/dashboard", response_model=VendorDashboardResponse)
async def vendor_dashboard(db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    vendors = VendorRepository.list_vendors(db, active_only=True)
    needing = VendorRepository.get_vendors_needing_assessment(db)

    risk_dist = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    scores = []
    for v in vendors:
        level = v.risk_level or "Medium"
        if level in risk_dist:
            risk_dist[level] += 1
        scores.append({
            "vendor": v.name,
            "vendor_id": v.id,
            "risk_level": level,
            "risk_score": v.risk_score,
            "criticality": v.criticality,
        })

    scores.sort(key=lambda x: x.get("risk_score") or 0, reverse=True)

    return VendorDashboardResponse(
        total_vendors=len(vendors),
        risk_distribution=risk_dist,
        vendors_needing_assessment=len(needing),
        expiring_contracts_90d=0,
        vendor_scores=scores,
    )


@router.get("/needing-assessment", response_model=list[VendorResponse])
async def vendors_needing_assessment(db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    vendors = VendorRepository.get_vendors_needing_assessment(db)
    return [_vendor_to_response(v) for v in vendors]


@router.get("/{vendor_id}", response_model=VendorResponse)
async def get_vendor(vendor_id: str, db: Session = Depends(get_db), api_key: str = Depends(require_api_key)):
    vendor = VendorRepository.get_vendor(db, vendor_id)
    if vendor is None:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return _vendor_to_response(vendor)


@router.put("/{vendor_id}", response_model=VendorResponse)
async def update_vendor(
    vendor_id: str, request: VendorUpdate, db: Session = Depends(get_db), api_key: str = Depends(require_api_key),
):
    updates = request.model_dump(exclude_none=True)
    updates = {k: v for k, v in updates.items() if k in VENDOR_UPDATABLE_FIELDS}
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    try:
        vendor = VendorRepository.update_vendor(db, vendor_id, updates)
    except ValueError:
        raise HTTPException(status_code=404, detail="Vendor not found")
    return _vendor_to_response(vendor)
