"""Tests for the framework mapper and export endpoints."""

from __future__ import annotations

import io
import json
import uuid
import zipfile
from datetime import UTC, datetime

import pytest

import db.session as db_session_module
from db.repository import AssessmentRepository, EvidenceRepository
from db.session import get_db_session
from modules.framework_mapper import FrameworkMapper

# ---------------------------------------------------------------------------
# 1. FrameworkMapper unit tests
# ---------------------------------------------------------------------------

SAMPLE_CROSSWALKS = {
    "nist_to_soc2": {
        "source": "nist_800_53",
        "target": "soc2",
        "mappings": {
            "AC-2": [
                {"control": "CC6.1", "confidence": "high", "notes": "Account management"},
                {"control": "CC6.2", "confidence": "medium", "notes": "Provisioning"},
            ],
            "AU-2": [
                {"control": "CC7.1", "confidence": "high", "notes": "Event logging"},
            ],
        },
    },
    "nist_to_iso27001": {
        "source": "nist_800_53",
        "target": "iso27001",
        "mappings": {
            "AC-2": [
                {"control": "A.5.15", "confidence": "high", "notes": "Access control"},
            ],
        },
    },
}


@pytest.fixture
def mapper():
    return FrameworkMapper(SAMPLE_CROSSWALKS)


class TestFrameworkMapper:

    def test_frameworks_list(self, mapper):
        fws = mapper.frameworks
        assert "nist_800_53" in fws
        assert "soc2" in fws
        assert "iso27001" in fws

    def test_direct_mapping_nist_to_soc2(self, mapper):
        results = mapper.map_control("nist_800_53", "AC-2", "soc2")
        assert len(results) == 2
        target_ids = {r.target_control_id for r in results}
        assert "CC6.1" in target_ids
        assert "CC6.2" in target_ids
        assert all(r.source_framework == "nist_800_53" for r in results)
        assert all(r.target_framework == "soc2" for r in results)

    def test_reverse_mapping_soc2_to_nist(self, mapper):
        results = mapper.map_control("soc2", "CC6.1", "nist_800_53")
        target_ids = {r.target_control_id for r in results}
        assert "AC-2" in target_ids

    def test_reverse_confidence_downgraded(self, mapper):
        results = mapper.map_control("soc2", "CC6.1", "nist_800_53")
        ac2 = [r for r in results if r.target_control_id == "AC-2"]
        assert ac2[0].confidence == "medium"  # downgraded from "high"

    def test_transitive_mapping_soc2_to_iso27001(self, mapper):
        results = mapper.map_control("soc2", "CC6.1", "iso27001")
        target_ids = {r.target_control_id for r in results}
        assert "A.5.15" in target_ids
        # Should have an intermediate framework
        transitive = [r for r in results if r.target_control_id == "A.5.15"]
        assert len(transitive[0].via) > 0

    def test_identity_mapping(self, mapper):
        results = mapper.map_control("nist_800_53", "AC-2", "nist_800_53")
        assert len(results) == 1
        assert results[0].target_control_id == "AC-2"
        assert results[0].confidence == "high"

    def test_unknown_control_returns_empty(self, mapper):
        results = mapper.map_control("nist_800_53", "XX-99", "soc2")
        assert results == []

    def test_unknown_framework_returns_empty(self, mapper):
        results = mapper.map_control("nonexistent", "AC-2", "soc2")
        assert results == []

    def test_get_available_mappings(self, mapper):
        targets = mapper.get_available_mappings("nist_800_53")
        assert "soc2" in targets
        assert "iso27001" in targets

    def test_get_available_mappings_reverse(self, mapper):
        targets = mapper.get_available_mappings("soc2")
        assert "nist_800_53" in targets

    def test_map_results_duplicates_for_multi_mapping(self, mapper):
        results = [{"control_id": "AC-2", "status": "pass", "check_id": "AC-2.a"}]
        mapped = mapper.map_results(results, "nist_800_53", "soc2")
        assert len(mapped) == 2  # AC-2 maps to CC6.1 and CC6.2
        assert mapped[0]["original_control_id"] == "AC-2"
        assert {m["control_id"] for m in mapped} == {"CC6.1", "CC6.2"}

    def test_map_results_unmapped_control(self, mapper):
        results = [{"control_id": "XX-99", "status": "fail"}]
        mapped = mapper.map_results(results, "nist_800_53", "soc2")
        assert len(mapped) == 1
        assert mapped[0]["mapping_confidence"] == "unmapped"
        assert mapped[0]["control_id"] == "XX-99"

    def test_map_results_same_framework(self, mapper):
        results = [{"control_id": "AC-2", "status": "pass"}]
        mapped = mapper.map_results(results, "nist_800_53", "nist_800_53")
        assert len(mapped) == 1
        assert mapped[0]["mapping_confidence"] == "high"
        assert mapped[0]["original_control_id"] == "AC-2"

    def test_map_evidence_same_as_results(self, mapper):
        evidence = [{"control_id": "AC-2", "provider": "aws"}]
        mapped = mapper.map_evidence(evidence, "nist_800_53", "soc2")
        assert len(mapped) == 2

    def test_from_yaml_loads_real_crosswalks(self):
        mapper = FrameworkMapper.from_yaml()
        if mapper.frameworks:  # file exists
            assert len(mapper.frameworks) > 0

    def test_from_yaml_missing_file(self, tmp_path):
        mapper = FrameworkMapper.from_yaml(str(tmp_path / "nonexistent.yaml"))
        assert mapper.frameworks == []

    def test_empty_crosswalks(self):
        mapper = FrameworkMapper({})
        assert mapper.frameworks == []
        assert mapper.map_control("a", "b", "c") == []


# ---------------------------------------------------------------------------
# 2. Export API endpoint tests
# ---------------------------------------------------------------------------

DB_URL = "sqlite://"


@pytest.fixture(autouse=True)
def _reset_caches():
    """Reset caches before each test."""
    # Reset export router's mapper cache
    import api.routers.exports as exports_mod
    exports_mod._mapper = None
    yield


@pytest.fixture
def client():
    import os
    os.environ.pop("GRC_API_KEYS", None)

    # Reset api key cache
    import api.security as sec
    sec._api_keys_cache = None

    # Reset DB so the lifespan init_db() creates fresh tables
    db_session_module._engine = None
    db_session_module._session_factory = None

    from fastapi.testclient import TestClient

    from api.main import app
    with TestClient(app) as c:
        yield c

    db_session_module._engine = None
    db_session_module._session_factory = None


@pytest.fixture
def seeded_run(client):
    """Create a completed assessment run with results and evidence.

    Must depend on `client` so the lifespan init_db() runs first.
    """

    with get_db_session() as session:
        run = AssessmentRepository.create_run(session, framework="nist_800_53")
        run_id = run.id

        AssessmentRepository.complete_run(
            session, run_id,
            total_checks=3, passed=2, failed=1, errors=0,
            summary={"pass_rate": "66.7%"},
        )

        for i, (ctrl, status) in enumerate([("AC-2", "pass"), ("AU-2", "pass"), ("SC-7", "fail")]):
            AssessmentRepository.save_result(
                session,
                result_id=str(uuid.uuid4()),
                run_id=run_id,
                control_id=ctrl,
                check_id=f"{ctrl}.a",
                assertion=f"test_assertion_{i}",
                status=status,
                severity="medium",
                provider="aws",
                region="us-east-1",
                findings=[f"Finding for {ctrl}"],
                evidence_ids=[],
                evidence_summary=f"Evidence for {ctrl}",
                remediation="Fix it" if status == "fail" else None,
            )

        # Add evidence records
        for ctrl in ["AC-2", "AU-2", "SC-7"]:
            EvidenceRepository.save_evidence(
                session,
                evidence_id=str(uuid.uuid4()),
                run_id=run_id,
                control_id=ctrl,
                check_id=f"{ctrl}.a",
                provider="aws",
                service="iam",
                resource_type="user",
                region="us-east-1",
                account_id="123456789012",
                collected_at=datetime.now(UTC),
                data={"test": True},
                normalized_data={"normalized": True},
                status="collected",
                sha256_hash="abc123",
            )

    return run_id


class TestExportAuditPackage:

    def test_returns_zip(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/audit-package",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "soc2",
            },
        )
        assert resp.status_code == 200
        assert resp.headers["content-type"] == "application/zip"
        assert "attachment" in resp.headers.get("content-disposition", "")

        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        names = zf.namelist()
        assert "manifest.json" in names
        assert "assessment_results.json" in names
        assert "summary.json" in names
        assert "poam.txt" in names
        assert "executive_summary.txt" in names

    def test_zip_contains_mapped_results(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/audit-package",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "soc2",
            },
        )
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        results = json.loads(zf.read("assessment_results.json"))
        # AC-2 maps to CC6.1 and CC6.2 in SOC2, so we get more results
        assert len(results) >= 3
        control_ids = {r["control_id"] for r in results}
        assert "CC6.1" in control_ids or "CC7.1" in control_ids

    def test_zip_contains_evidence(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/audit-package",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "nist_800_53",
            },
        )
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        evidence_files = [n for n in zf.namelist() if n.startswith("evidence/")]
        assert len(evidence_files) == 3

    def test_exclude_optional_sections(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/audit-package",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "nist_800_53",
                "include_evidence": False,
                "include_poam": False,
                "include_executive_summary": False,
            },
        )
        assert resp.status_code == 200
        zf = zipfile.ZipFile(io.BytesIO(resp.content))
        names = zf.namelist()
        assert "poam.txt" not in names
        assert "executive_summary.txt" not in names
        evidence_files = [n for n in names if n.startswith("evidence/")]
        assert len(evidence_files) == 0

    def test_run_not_found(self, client):
        resp = client.get(
            "/api/v1/export/audit-package",
            params={
                "assessment_run_id": "nonexistent",
                "target_framework": "soc2",
            },
        )
        assert resp.status_code == 404


class TestExportPoam:

    def test_poam_txt(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/poam",
            params={"assessment_run_id": seeded_run, "format": "txt"},
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "POAM" in resp.text or "POA&M" in resp.text or "Plan of Action" in resp.text

    def test_poam_json(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/poam",
            params={"assessment_run_id": seeded_run, "format": "json"},
        )
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert "items" in data
        assert "metadata" in data
        assert data["total_findings"] >= 1

    def test_poam_with_mapping(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/poam",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "soc2",
                "format": "json",
            },
        )
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["metadata"]["framework"] == "soc2"

    def test_poam_invalid_format(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/poam",
            params={"assessment_run_id": seeded_run, "format": "pdf"},
        )
        assert resp.status_code == 422


class TestExportEvidence:

    def test_evidence_json(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/evidence",
            params={"assessment_run_id": seeded_run, "format": "json"},
        )
        assert resp.status_code == 200
        data = json.loads(resp.content)
        assert data["metadata"]["total"] == 3
        assert len(data["evidence"]) == 3

    def test_evidence_csv(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/evidence",
            params={"assessment_run_id": seeded_run, "format": "csv"},
        )
        assert resp.status_code == 200
        assert "text/csv" in resp.headers["content-type"]
        lines = resp.text.strip().split("\n")
        assert len(lines) == 4  # header + 3 rows

    def test_evidence_filter_by_family(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/evidence",
            params={
                "assessment_run_id": seeded_run,
                "control_family": "AC",
                "format": "json",
            },
        )
        data = json.loads(resp.content)
        assert data["metadata"]["total"] == 1
        assert all(e["control_id"].startswith("AC") for e in data["evidence"])

    def test_evidence_with_mapping(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/evidence",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "soc2",
                "format": "json",
            },
        )
        data = json.loads(resp.content)
        # Mapped evidence may have more entries due to multi-mapping
        assert data["metadata"]["total"] >= 3

    def test_evidence_invalid_format(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/evidence",
            params={"assessment_run_id": seeded_run, "format": "xml"},
        )
        assert resp.status_code == 422


class TestExportExecutiveSummary:

    def test_executive_summary(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/executive-summary",
            params={"assessment_run_id": seeded_run},
        )
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]

    def test_executive_summary_with_mapping(self, client, seeded_run):
        resp = client.get(
            "/api/v1/export/executive-summary",
            params={
                "assessment_run_id": seeded_run,
                "target_framework": "iso27001",
            },
        )
        assert resp.status_code == 200

    def test_executive_summary_not_found(self, client):
        resp = client.get(
            "/api/v1/export/executive-summary",
            params={"assessment_run_id": "nonexistent"},
        )
        assert resp.status_code == 404


class TestExportFrameworks:

    def test_list_all_frameworks(self, client):
        resp = client.get("/api/v1/export/frameworks")
        assert resp.status_code == 200
        data = resp.json()
        assert "frameworks" in data

    def test_list_mappings_for_framework(self, client):
        resp = client.get(
            "/api/v1/export/frameworks",
            params={"framework": "nist_800_53"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "available_targets" in data
        assert "soc2" in data["available_targets"]
