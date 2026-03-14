"""Framework management and crosswalk endpoints."""

from __future__ import annotations

from pathlib import Path

import yaml
from fastapi import APIRouter, Depends, HTTPException

from api.schemas import (
    CrosswalkRequest,
    CrosswalkResponse,
    FrameworkDetailResponse,
    FrameworkResponse,
)
from api.security import require_api_key

router = APIRouter(prefix="/api/v1/frameworks", tags=["frameworks"])

_frameworks_cache: dict | None = None
_crosswalks_cache: dict | None = None


def _load_frameworks() -> dict:
    global _frameworks_cache
    if _frameworks_cache is not None:
        return _frameworks_cache
    path = Path("config/frameworks.yaml")
    if not path.exists():
        return {}
    with open(path) as f:
        _frameworks_cache = yaml.safe_load(f) or {}
    return _frameworks_cache


def _load_crosswalks() -> dict:
    global _crosswalks_cache
    if _crosswalks_cache is not None:
        return _crosswalks_cache
    path = Path("config/crosswalks.yaml")
    if not path.exists():
        return {}
    with open(path) as f:
        data = yaml.safe_load(f) or {}
    _crosswalks_cache = data.get("crosswalks", {})
    return _crosswalks_cache


@router.get("/", response_model=list[FrameworkResponse])
async def list_frameworks(api_key: str = Depends(require_api_key)):
    frameworks = _load_frameworks()
    results = []
    for key, fw in frameworks.items():
        families = fw.get("control_families", {})
        control_count = sum(
            len(fam.get("controls", {}))
            for fam in families.values()
        )
        results.append(FrameworkResponse(
            id=key,
            name=key,
            display_name=fw.get("name", key),
            version=fw.get("version", ""),
            control_count=control_count,
            is_active=True,
        ))
    return results


@router.get("/{framework_id}", response_model=FrameworkDetailResponse)
async def get_framework(framework_id: str, api_key: str = Depends(require_api_key)):
    frameworks = _load_frameworks()
    fw = frameworks.get(framework_id)
    if fw is None:
        raise HTTPException(status_code=404, detail="Framework not found")

    families = fw.get("control_families", {})
    control_count = sum(len(fam.get("controls", {})) for fam in families.values())

    return FrameworkDetailResponse(
        id=framework_id,
        name=framework_id,
        display_name=fw.get("name", framework_id),
        version=fw.get("version", ""),
        control_count=control_count,
        is_active=True,
        description=fw.get("description"),
        control_families=families,
    )


@router.get("/{framework_id}/controls")
async def list_controls(framework_id: str, api_key: str = Depends(require_api_key)):
    frameworks = _load_frameworks()
    fw = frameworks.get(framework_id)
    if fw is None:
        raise HTTPException(status_code=404, detail="Framework not found")

    controls = []
    for family_id, family in fw.get("control_families", {}).items():
        for ctrl_id, ctrl in family.get("controls", {}).items():
            controls.append({
                "family": family_id,
                "family_name": family.get("name", ""),
                "control_id": ctrl_id,
                "title": ctrl.get("title", ""),
                "description": ctrl.get("description", ""),
                "check_count": len(ctrl.get("checks", [])),
            })
    return controls


@router.post("/crosswalk", response_model=CrosswalkResponse)
async def crosswalk_control(request: CrosswalkRequest, api_key: str = Depends(require_api_key)):
    crosswalks = _load_crosswalks()

    # Find the right crosswalk mapping
    mapping_key = f"{request.source_framework}_to_{request.target_framework}"
    # Try direct key lookup first, then search by source/target fields
    crosswalk = crosswalks.get(mapping_key)
    if crosswalk is None:
        for _key, cw in crosswalks.items():
            src = cw.get("source", "")
            tgt = cw.get("target", "")
            if src == request.source_framework and tgt == request.target_framework:
                crosswalk = cw
                break

    if crosswalk is None:
        raise HTTPException(
            status_code=404,
            detail=f"No crosswalk found from {request.source_framework} to {request.target_framework}",
        )

    mappings = crosswalk.get("mappings", {})
    targets = mappings.get(request.control_id, [])

    return CrosswalkResponse(
        source_framework=request.source_framework,
        source_control=request.control_id,
        target_controls=targets,
    )
