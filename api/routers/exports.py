"""
Audit export endpoints for framework-agnostic evidence packaging.

Provides downloadable POA&M documents, evidence exports, executive
summaries, and full audit packages — with optional crosswalk mapping
to any target framework.
"""

from __future__ import annotations

import csv
import io
import json
import logging
import tempfile
import zipfile
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from api.security import require_api_key
from db.repository import AssessmentRepository, EvidenceRepository
from db.session import get_db_session
from modules.framework_mapper import FrameworkMapper
from modules.report_generator import ReportGenerator

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/export", tags=["exports"])

_mapper: FrameworkMapper | None = None


def _get_mapper() -> FrameworkMapper:
    global _mapper
    if _mapper is None:
        _mapper = FrameworkMapper.from_yaml()
    return _mapper


def _result_to_dict(r) -> dict:
    """Convert an AssessmentResultRecord ORM object to a plain dict."""
    return {
        "id": r.id,
        "control_id": r.control_id,
        "check_id": r.check_id,
        "assertion": r.assertion,
        "status": r.status,
        "severity": r.severity,
        "provider": r.provider,
        "region": r.region,
        "findings": r.findings or [],
        "evidence_summary": r.evidence_summary or "",
        "remediation": r.remediation,
        "assessed_at": r.assessed_at.isoformat() if r.assessed_at else "",
    }


def _evidence_to_dict(e) -> dict:
    """Convert an EvidenceRecord ORM object to a plain dict."""
    return {
        "id": e.id,
        "control_id": e.control_id,
        "check_id": e.check_id,
        "provider": e.provider,
        "service": e.service,
        "resource_type": e.resource_type,
        "region": e.region,
        "account_id": e.account_id,
        "collected_at": e.collected_at.isoformat() if e.collected_at else "",
        "status": e.status,
        "sha256_hash": e.sha256_hash or "",
        "normalized_data": e.normalized_data or {},
    }


def _load_run_and_results(run_id: str) -> tuple:
    """Load an assessment run and its results. Raises HTTPException on failure."""
    with get_db_session() as session:
        run = AssessmentRepository.get_run(session, run_id)
        if run is None:
            raise HTTPException(status_code=404, detail="Assessment run not found")
        results = AssessmentRepository.get_results(session, run_id)
        result_dicts = [_result_to_dict(r) for r in results]
        run_data = {
            "id": run.id,
            "framework": run.framework,
            "status": run.status,
            "started_at": run.started_at.isoformat() if run.started_at else "",
            "completed_at": run.completed_at.isoformat() if run.completed_at else "",
            "total_checks": run.total_checks,
            "passed": run.passed,
            "failed": run.failed,
            "errors": run.errors,
            "pass_rate": run.pass_rate,
            "summary": run.summary,
        }
    return run_data, result_dicts


def _apply_mapping(
    result_dicts: list[dict],
    source_framework: str,
    target_framework: str | None,
) -> tuple[list[dict], bool]:
    """Apply framework mapping if target differs from source. Returns (mapped_results, was_mapped)."""
    if not target_framework or target_framework == source_framework:
        return result_dicts, False
    mapper = _get_mapper()
    return mapper.map_results(result_dicts, source_framework, target_framework), True


def _build_summary(result_dicts: list[dict]) -> dict:
    """Build assessment summary stats from result dicts."""
    total = len(result_dicts)
    passed = sum(1 for r in result_dicts if r.get("status") == "pass")
    failed = sum(1 for r in result_dicts if r.get("status") == "fail")
    errors = sum(1 for r in result_dicts if r.get("status") == "error")
    not_assessed = total - passed - failed - errors

    # Build by_control family breakdown
    by_control: dict[str, dict[str, int]] = {}
    for r in result_dicts:
        ctrl = r.get("control_id", "")
        family = ctrl.split("-")[0] if "-" in ctrl else ctrl
        if family not in by_control:
            by_control[family] = {"pass": 0, "fail": 0, "error": 0}
        status = r.get("status", "")
        if status in by_control[family]:
            by_control[family][status] += 1

    return {
        "total_checks": total,
        "passed": passed,
        "failed": failed,
        "errors": errors,
        "not_assessed": not_assessed,
        "pass_rate": f"{passed / total * 100:.1f}%" if total > 0 else "N/A",
        "by_control": by_control,
    }


# ── Audit Package (ZIP) ─────────────────────────────────────────────


@router.get("/audit-package")
async def export_audit_package(
    assessment_run_id: str = Query(..., description="Assessment run to export"),
    target_framework: str = Query(..., description="Target framework for control mapping"),
    include_evidence: bool = Query(True, description="Include evidence in package"),
    include_poam: bool = Query(True, description="Include POA&M document"),
    include_executive_summary: bool = Query(True, description="Include executive summary"),
    api_key: str = Depends(require_api_key),
):
    run_data, result_dicts = _load_run_and_results(assessment_run_id)
    source_fw = run_data["framework"]
    mapped_results, was_mapped = _apply_mapping(result_dicts, source_fw, target_framework)
    summary = _build_summary(mapped_results)
    report_gen = ReportGenerator()

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Manifest
        manifest = {
            "source_framework": source_fw,
            "target_framework": target_framework,
            "mapping_applied": was_mapped,
            "assessment_run_id": assessment_run_id,
            "generated_at": datetime.now(UTC).isoformat(),
            "files": [],
        }

        # Assessment results
        zf.writestr(
            "assessment_results.json",
            json.dumps(mapped_results, indent=2, default=str),
        )
        manifest["files"].append("assessment_results.json")

        # Summary
        zf.writestr("summary.json", json.dumps(summary, indent=2))
        manifest["files"].append("summary.json")

        # POA&M
        if include_poam:
            with tempfile.TemporaryDirectory() as tmpdir:
                poam_path = f"{tmpdir}/poam.txt"
                report_gen.generate_poam(mapped_results, poam_path)
                with open(poam_path) as f:
                    zf.writestr("poam.txt", f.read())
            manifest["files"].append("poam.txt")

        # Executive Summary
        if include_executive_summary:
            with tempfile.TemporaryDirectory() as tmpdir:
                summary_path = f"{tmpdir}/executive_summary.txt"
                report_gen.generate_executive_summary(
                    summary, mapped_results, summary_path,
                    framework=target_framework,
                )
                with open(summary_path) as f:
                    zf.writestr("executive_summary.txt", f.read())
            manifest["files"].append("executive_summary.txt")

        # Evidence
        if include_evidence:
            with get_db_session() as session:
                evidence_records = EvidenceRepository.get_evidence_by_run(
                    session, assessment_run_id
                )
                evidence_dicts = [_evidence_to_dict(e) for e in evidence_records]

            if was_mapped:
                mapper = _get_mapper()
                evidence_dicts = mapper.map_evidence(evidence_dicts, source_fw, target_framework)

            for ev in evidence_dicts:
                filename = f"evidence/{ev.get('control_id', 'unknown')}_{ev.get('id', 'unknown')}.json"
                zf.writestr(filename, json.dumps(ev, indent=2, default=str))
            manifest["files"].append(f"evidence/ ({len(evidence_dicts)} files)")

        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    buf.seek(0)
    filename = f"audit_package_{target_framework}_{assessment_run_id[:8]}.zip"
    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


# ── POA&M Export ─────────────────────────────────────────────────────


@router.get("/poam")
async def export_poam(
    assessment_run_id: str = Query(...),
    target_framework: str | None = Query(None, description="Remap controls to target framework"),
    format: str = Query("txt", description="Output format: txt or json"),
    api_key: str = Depends(require_api_key),
):
    if format not in ("txt", "json"):
        raise HTTPException(status_code=422, detail="Format must be 'txt' or 'json'")

    run_data, result_dicts = _load_run_and_results(assessment_run_id)
    source_fw = run_data["framework"]
    mapped_results, _ = _apply_mapping(result_dicts, source_fw, target_framework)
    report_gen = ReportGenerator()

    if format == "json":
        failures = [r for r in mapped_results if r.get("status") == "fail"]
        poam_items = []
        for i, result in enumerate(failures, 1):
            poam_items.append({
                "poam_id": f"POAM-{i:04d}",
                "control_id": result.get("control_id", ""),
                "original_control_id": result.get("original_control_id", result.get("control_id", "")),
                "check_id": result.get("check_id", ""),
                "status": "Open",
                "severity": result.get("severity", "medium"),
                "provider": result.get("provider", ""),
                "region": result.get("region", ""),
                "findings": result.get("findings", []),
                "remediation": result.get("remediation", "See framework guidance"),
            })
        return Response(
            content=json.dumps({
                "metadata": {
                    "assessment_run_id": assessment_run_id,
                    "framework": target_framework or source_fw,
                    "generated_at": datetime.now(UTC).isoformat(),
                },
                "total_findings": len(poam_items),
                "items": poam_items,
            }, indent=2, default=str),
            media_type="application/json",
            headers={"Content-Disposition": f'attachment; filename="poam_{assessment_run_id[:8]}.json"'},
        )

    # Text format
    with tempfile.TemporaryDirectory() as tmpdir:
        poam_path = f"{tmpdir}/poam.txt"
        report_gen.generate_poam(mapped_results, poam_path)
        with open(poam_path) as f:
            content = f.read()

    return Response(
        content=content,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="poam_{assessment_run_id[:8]}.txt"'},
    )


# ── Evidence Export ──────────────────────────────────────────────────


@router.get("/evidence")
async def export_evidence(
    assessment_run_id: str | None = Query(None),
    target_framework: str | None = Query(None),
    control_family: str | None = Query(None, description="Filter by control family prefix"),
    format: str = Query("json", description="Output format: json or csv"),
    api_key: str = Depends(require_api_key),
):
    if format not in ("json", "csv"):
        raise HTTPException(status_code=422, detail="Format must be 'json' or 'csv'")

    with get_db_session() as session:
        if assessment_run_id:
            records = EvidenceRepository.get_evidence_by_run(session, assessment_run_id)
        else:
            records = EvidenceRepository.list_evidence(session, limit=10000)
        evidence_dicts = [_evidence_to_dict(e) for e in records]

    # Filter by control family prefix
    if control_family:
        evidence_dicts = [
            e for e in evidence_dicts
            if e.get("control_id", "").startswith(control_family)
        ]

    # Apply framework mapping
    if target_framework and assessment_run_id:
        with get_db_session() as session:
            run = AssessmentRepository.get_run(session, assessment_run_id)
            source_fw = run.framework if run else "nist_800_53"
        if target_framework != source_fw:
            mapper = _get_mapper()
            evidence_dicts = mapper.map_evidence(evidence_dicts, source_fw, target_framework)

    if format == "csv":
        output = io.StringIO()
        if evidence_dicts:
            writer = csv.DictWriter(output, fieldnames=list(evidence_dicts[0].keys()))
            writer.writeheader()
            for row in evidence_dicts:
                # Flatten nested dicts for CSV
                flat = {}
                for k, v in row.items():
                    flat[k] = json.dumps(v) if isinstance(v, (dict, list)) else v
                writer.writerow(flat)
        return Response(
            content=output.getvalue(),
            media_type="text/csv",
            headers={"Content-Disposition": 'attachment; filename="evidence_export.csv"'},
        )

    return Response(
        content=json.dumps({
            "metadata": {
                "total": len(evidence_dicts),
                "assessment_run_id": assessment_run_id,
                "target_framework": target_framework,
                "control_family_filter": control_family,
                "generated_at": datetime.now(UTC).isoformat(),
            },
            "evidence": evidence_dicts,
        }, indent=2, default=str),
        media_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="evidence_export.json"'},
    )


# ── Executive Summary Export ─────────────────────────────────────────


@router.get("/executive-summary")
async def export_executive_summary(
    assessment_run_id: str = Query(...),
    target_framework: str | None = Query(None),
    api_key: str = Depends(require_api_key),
):
    run_data, result_dicts = _load_run_and_results(assessment_run_id)
    source_fw = run_data["framework"]
    mapped_results, _ = _apply_mapping(result_dicts, source_fw, target_framework)
    summary = _build_summary(mapped_results)
    report_gen = ReportGenerator()

    display_framework = target_framework or source_fw

    with tempfile.TemporaryDirectory() as tmpdir:
        summary_path = f"{tmpdir}/executive_summary.txt"
        report_gen.generate_executive_summary(
            summary, mapped_results, summary_path,
            framework=display_framework,
        )
        with open(summary_path) as f:
            content = f.read()

    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="executive_summary_{assessment_run_id[:8]}.txt"'
        },
    )


# ── Framework Mapping Info ───────────────────────────────────────────


@router.get("/frameworks")
async def list_available_mappings(
    framework: str | None = Query(None, description="Show mappings from this framework"),
    api_key: str = Depends(require_api_key),
):
    """List available frameworks and their mapping targets."""
    mapper = _get_mapper()
    if framework:
        return {
            "framework": framework,
            "available_targets": mapper.get_available_mappings(framework),
        }
    return {
        "frameworks": mapper.frameworks,
    }
