"""
Comprehensive tests for the GRC Toolkit FastAPI API.

Tests cover:
- Health endpoint
- Security (API key auth, enum validation, constant-time compare)
- Evidence endpoints
- Assessment endpoints
- Risk simulation endpoints
- Framework endpoints
- Vendor CRUD endpoints
- Policy endpoints
- Middleware (security headers, request IDs, rate limit headers)
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _reset_caches(tmp_path, monkeypatch):
    """Reset all module-level caches and point DB at a fresh in-memory SQLite."""
    import api.deps as deps
    import api.routers.frameworks as fw_mod
    import api.security as sec
    import db.session as sess

    # Use an in-memory SQLite database for every test
    monkeypatch.setenv("GRC_DATABASE_URL", "sqlite://")

    # Raise the rate limit so tests don't hit 429
    monkeypatch.setenv("GRC_RATE_LIMIT_RPM", "60000")
    monkeypatch.setenv("GRC_RATE_LIMIT_BURST", "10000")

    # Clear API key cache so each test can set its own GRC_API_KEYS
    sec._api_keys_cache = None

    # Clear DB engine / session factory caches so we get a fresh DB
    sess._engine = None
    sess._session_factory = None

    # Clear settings cache
    deps._settings_cache = None

    # Clear framework / crosswalk caches
    fw_mod._frameworks_cache = None
    fw_mod._crosswalks_cache = None

    # Remove GRC_API_KEYS by default (dev / anonymous mode)
    monkeypatch.delenv("GRC_API_KEYS", raising=False)

    yield

    # Teardown: reset again to avoid contaminating other test modules
    sec._api_keys_cache = None
    sess._engine = None
    sess._session_factory = None
    deps._settings_cache = None
    fw_mod._frameworks_cache = None
    fw_mod._crosswalks_cache = None


@pytest.fixture()
def client():
    """Return a fresh TestClient that triggers the lifespan (DB init)."""
    from api.main import app
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# 1. Health endpoint
# ---------------------------------------------------------------------------

class TestHealth:
    def test_health_returns_200(self, client: TestClient):
        resp = client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "healthy"
        assert "timestamp" in data

    def test_health_has_request_id(self, client: TestClient):
        resp = client.get("/health")
        # AuditLogMiddleware adds X-Request-Id
        assert "x-request-id" in resp.headers


# ---------------------------------------------------------------------------
# 2. Security helpers (unit-level)
# ---------------------------------------------------------------------------

class TestSecurityHelpers:
    def test_constant_time_compare_equal(self):
        from api.security import _constant_time_compare
        assert _constant_time_compare("secret123", "secret123") is True

    def test_constant_time_compare_unequal(self):
        from api.security import _constant_time_compare
        assert _constant_time_compare("secret123", "wrong") is False

    def test_constant_time_compare_empty(self):
        from api.security import _constant_time_compare
        assert _constant_time_compare("", "") is True

    def test_validate_enum_valid(self):
        from api.security import validate_enum
        result = validate_enum("aws", {"aws", "azure", "gcp"}, "provider")
        assert result == "aws"

    def test_validate_enum_invalid(self):
        from fastapi import HTTPException

        from api.security import validate_enum
        with pytest.raises(HTTPException) as exc_info:
            validate_enum("oracle", {"aws", "azure", "gcp"}, "provider")
        assert exc_info.value.status_code == 422
        assert "oracle" in exc_info.value.detail


# ---------------------------------------------------------------------------
# 3. API key authentication (via real requests)
# ---------------------------------------------------------------------------

class TestAPIKeyAuth:
    def test_dev_mode_no_keys_allows_access(self, client: TestClient):
        """When GRC_API_KEYS is unset, all requests succeed (anonymous)."""
        resp = client.get("/api/v1/evidence/")
        assert resp.status_code == 200

    def test_missing_key_returns_401(self, monkeypatch, client: TestClient):
        import api.security as sec
        monkeypatch.setenv("GRC_API_KEYS", "valid-key-1,valid-key-2")
        sec._api_keys_cache = None

        resp = client.get("/api/v1/evidence/")
        assert resp.status_code == 401
        assert "Missing API key" in resp.json()["detail"]

    def test_invalid_key_returns_403(self, monkeypatch, client: TestClient):
        import api.security as sec
        monkeypatch.setenv("GRC_API_KEYS", "valid-key-1")
        sec._api_keys_cache = None

        resp = client.get(
            "/api/v1/evidence/",
            headers={"X-API-Key": "wrong-key"},
        )
        assert resp.status_code == 403
        assert "Invalid API key" in resp.json()["detail"]

    def test_valid_key_succeeds(self, monkeypatch, client: TestClient):
        import api.security as sec
        monkeypatch.setenv("GRC_API_KEYS", "valid-key-1")
        sec._api_keys_cache = None

        resp = client.get(
            "/api/v1/evidence/",
            headers={"X-API-Key": "valid-key-1"},
        )
        assert resp.status_code == 200

    def test_second_valid_key_succeeds(self, monkeypatch, client: TestClient):
        import api.security as sec
        monkeypatch.setenv("GRC_API_KEYS", "key-a,key-b")
        sec._api_keys_cache = None

        resp = client.get(
            "/api/v1/evidence/",
            headers={"X-API-Key": "key-b"},
        )
        assert resp.status_code == 200


# ---------------------------------------------------------------------------
# 4. Evidence endpoints
# ---------------------------------------------------------------------------

class TestEvidence:
    def test_list_evidence_empty(self, client: TestClient):
        resp = client.get("/api/v1/evidence/")
        assert resp.status_code == 200
        data = resp.json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["page_size"] == 50

    def test_collect_returns_202(self, client: TestClient):
        resp = client.post(
            "/api/v1/evidence/collect",
            json={
                "framework": "nist_800_53",
                "providers": ["aws"],
            },
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["status"] == "pending"
        assert "run_id" in data
        assert data["artifacts_collected"] == 0

    def test_collect_default_body(self, client: TestClient):
        resp = client.post("/api/v1/evidence/collect", json={})
        assert resp.status_code == 202

    def test_get_evidence_not_found(self, client: TestClient):
        resp = client.get("/api/v1/evidence/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 5. Assessment endpoints
# ---------------------------------------------------------------------------

class TestAssessments:
    def test_list_runs_empty(self, client: TestClient):
        resp = client.get("/api/v1/assessments/runs")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_trend_empty(self, client: TestClient):
        resp = client.get("/api/v1/assessments/trend")
        assert resp.status_code == 200
        data = resp.json()
        assert data["runs"] == []

    def test_trend_with_framework_param(self, client: TestClient):
        resp = client.get("/api/v1/assessments/trend?framework=soc2&last_n=5")
        assert resp.status_code == 200
        assert resp.json()["runs"] == []

    def test_trigger_assessment_run(self, client: TestClient):
        resp = client.post(
            "/api/v1/assessments/run",
            json={"framework": "nist_800_53"},
        )
        assert resp.status_code == 202
        data = resp.json()
        assert data["framework"] == "nist_800_53"
        assert data["status"] == "running"
        assert "id" in data

    def test_get_run_not_found(self, client: TestClient):
        resp = client.get("/api/v1/assessments/runs/nonexistent-id")
        assert resp.status_code == 404


# ---------------------------------------------------------------------------
# 6. Risk endpoints (no DB needed — in-memory Monte Carlo)
# ---------------------------------------------------------------------------

SAMPLE_SCENARIO = {
    "name": "Ransomware",
    "description": "Ransomware attack scenario",
    "category": "Malware",
    "frequency_min": 0.5,
    "frequency_mode": 1.0,
    "frequency_max": 3.0,
    "impact_min": 50000,
    "impact_mode": 200000,
    "impact_max": 1000000,
    "control_effectiveness": 0.3,
}


class TestRisk:
    def test_simulate_scenario(self, client: TestClient):
        resp = client.post(
            "/api/v1/risk/simulate?iterations=500&seed=42",
            json=SAMPLE_SCENARIO,
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["scenario_name"] == "Ransomware"
        assert data["iterations"] == 500
        assert data["mean_ale"] > 0
        assert data["var_95"] >= data["median_ale"]

    def test_simulate_deterministic_seed(self, client: TestClient):
        """Same seed should yield same results."""
        resp1 = client.post(
            "/api/v1/risk/simulate?iterations=1000&seed=99",
            json=SAMPLE_SCENARIO,
        )
        resp2 = client.post(
            "/api/v1/risk/simulate?iterations=1000&seed=99",
            json=SAMPLE_SCENARIO,
        )
        assert resp1.json()["mean_ale"] == resp2.json()["mean_ale"]

    def test_list_scenarios(self, client: TestClient):
        resp = client.get("/api/v1/risk/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "name" in data[0]
        assert "frequency" in data[0]
        assert "impact" in data[0]

    def test_portfolio_simulation(self, client: TestClient):
        resp = client.post(
            "/api/v1/risk/portfolio",
            json={
                "scenarios": [SAMPLE_SCENARIO],
                "iterations": 500,
                "seed": 42,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "scenarios" in data
        assert "aggregate" in data
        assert "scenario_ranking" in data
        assert len(data["scenarios"]) == 1

    def test_treatments_comparison(self, client: TestClient):
        resp = client.post(
            "/api/v1/risk/treatments",
            json={
                "scenario": SAMPLE_SCENARIO,
                "treatments": [
                    {"name": "EDR", "effectiveness": 0.6, "annual_cost": 50000},
                    {"name": "Training", "effectiveness": 0.2, "annual_cost": 10000},
                ],
                "iterations": 500,
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert "treatments" in data
        # Includes the two requested treatments plus a baseline
        assert len(data["treatments"]) >= 2


# ---------------------------------------------------------------------------
# 7. Framework endpoints
# ---------------------------------------------------------------------------

class TestFrameworks:
    def test_list_frameworks(self, client: TestClient):
        resp = client.get("/api/v1/frameworks/")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # frameworks.yaml has at least nist_800_53
        names = [fw["id"] for fw in data]
        assert "nist_800_53" in names

    def test_get_framework_detail(self, client: TestClient):
        resp = client.get("/api/v1/frameworks/nist_800_53")
        assert resp.status_code == 200
        data = resp.json()
        assert data["id"] == "nist_800_53"
        assert data["control_count"] > 0
        assert "control_families" in data

    def test_get_framework_not_found(self, client: TestClient):
        resp = client.get("/api/v1/frameworks/nonexistent")
        assert resp.status_code == 404

    def test_list_controls(self, client: TestClient):
        resp = client.get("/api/v1/frameworks/nist_800_53/controls")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) > 0
        assert "control_id" in data[0]

    def test_crosswalk(self, client: TestClient):
        resp = client.post(
            "/api/v1/frameworks/crosswalk",
            json={
                "source_framework": "nist_800_53",
                "control_id": "AC-2",
                "target_framework": "soc2",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["source_framework"] == "nist_800_53"
        assert data["source_control"] == "AC-2"
        assert isinstance(data["target_controls"], list)
        assert len(data["target_controls"]) > 0

    def test_crosswalk_not_found(self, client: TestClient):
        resp = client.post(
            "/api/v1/frameworks/crosswalk",
            json={
                "source_framework": "nist_800_53",
                "control_id": "AC-2",
                "target_framework": "nonexistent_framework",
            },
        )
        assert resp.status_code == 404

    def test_crosswalk_unknown_control(self, client: TestClient):
        """A valid crosswalk mapping but unknown control returns empty list."""
        resp = client.post(
            "/api/v1/frameworks/crosswalk",
            json={
                "source_framework": "nist_800_53",
                "control_id": "ZZ-999",
                "target_framework": "soc2",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["target_controls"] == []


# ---------------------------------------------------------------------------
# 8. Vendor endpoints
# ---------------------------------------------------------------------------

SAMPLE_VENDOR = {
    "name": "Acme Cloud",
    "category": "SaaS",
    "criticality": "High",
    "data_classification": "Confidential",
    "contract_start": "2025-01-01",
    "contract_end": "2026-12-31",
    "certifications": ["SOC2", "ISO27001"],
    "assessment_frequency_days": 180,
    "primary_contact": "vendor@acme.example",
    "notes": "Test vendor",
}


class TestVendors:
    def test_create_vendor(self, client: TestClient):
        resp = client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "Acme Cloud"
        assert data["category"] == "SaaS"
        assert data["criticality"] == "High"
        assert data["certifications"] == ["SOC2", "ISO27001"]
        assert "id" in data

    def test_list_vendors(self, client: TestClient):
        # Create one first
        client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)

        resp = client.get("/api/v1/vendors/")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_vendors_empty(self, client: TestClient):
        resp = client.get("/api/v1/vendors/")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_get_vendor(self, client: TestClient):
        create_resp = client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)
        vendor_id = create_resp.json()["id"]

        resp = client.get(f"/api/v1/vendors/{vendor_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == vendor_id

    def test_get_vendor_not_found(self, client: TestClient):
        resp = client.get("/api/v1/vendors/nonexistent-id")
        assert resp.status_code == 404

    def test_update_vendor(self, client: TestClient):
        create_resp = client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)
        vendor_id = create_resp.json()["id"]

        resp = client.put(
            f"/api/v1/vendors/{vendor_id}",
            json={"name": "Acme Cloud v2", "risk_score": 72.5},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["name"] == "Acme Cloud v2"
        assert data["risk_score"] == 72.5

    def test_update_vendor_not_found(self, client: TestClient):
        resp = client.put(
            "/api/v1/vendors/nonexistent-id",
            json={"name": "New Name"},
        )
        assert resp.status_code == 404

    def test_update_vendor_no_fields(self, client: TestClient):
        create_resp = client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)
        vendor_id = create_resp.json()["id"]

        resp = client.put(f"/api/v1/vendors/{vendor_id}", json={})
        assert resp.status_code == 400
        assert "No fields to update" in resp.json()["detail"]

    def test_create_vendor_invalid_criticality(self, client: TestClient):
        bad_vendor = {**SAMPLE_VENDOR, "criticality": "Ultra"}
        resp = client.post("/api/v1/vendors/", json=bad_vendor)
        assert resp.status_code == 422

    def test_create_vendor_invalid_category(self, client: TestClient):
        bad_vendor = {**SAMPLE_VENDOR, "category": "BadCategory"}
        resp = client.post("/api/v1/vendors/", json=bad_vendor)
        assert resp.status_code == 422

    def test_create_vendor_invalid_data_classification(self, client: TestClient):
        bad_vendor = {**SAMPLE_VENDOR, "data_classification": "TopSecret"}
        resp = client.post("/api/v1/vendors/", json=bad_vendor)
        assert resp.status_code == 422

    def test_create_vendor_contract_dates_invalid(self, client: TestClient):
        bad_vendor = {
            **SAMPLE_VENDOR,
            "contract_start": "2026-01-01",
            "contract_end": "2025-01-01",
        }
        resp = client.post("/api/v1/vendors/", json=bad_vendor)
        assert resp.status_code == 422

    def test_vendor_dashboard_empty(self, client: TestClient):
        resp = client.get("/api/v1/vendors/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vendors"] == 0
        assert data["vendors_needing_assessment"] == 0

    def test_vendor_dashboard_with_data(self, client: TestClient):
        client.post("/api/v1/vendors/", json=SAMPLE_VENDOR)
        resp = client.get("/api/v1/vendors/dashboard")
        assert resp.status_code == 200
        data = resp.json()
        assert data["total_vendors"] == 1
        assert "risk_distribution" in data
        assert "vendor_scores" in data


# ---------------------------------------------------------------------------
# 9. Policy endpoints
# ---------------------------------------------------------------------------

class TestPolicies:
    def test_list_violations_empty(self, client: TestClient):
        resp = client.get("/api/v1/policies/violations")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_list_bundles(self, client: TestClient):
        resp = client.get("/api/v1/policies/bundles")
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        # The policies/ directory has sub-dirs like nist-800-53, soc2, terraform
        if len(data) > 0:
            assert "name" in data[0]
            assert "policy_count" in data[0]


# ---------------------------------------------------------------------------
# 10. Middleware tests
# ---------------------------------------------------------------------------

class TestMiddleware:
    def test_security_headers_present(self, client: TestClient):
        resp = client.get("/health")
        headers = resp.headers
        assert headers["x-content-type-options"] == "nosniff"
        assert headers["x-frame-options"] == "DENY"
        assert headers["x-xss-protection"] == "1; mode=block"
        assert headers["referrer-policy"] == "strict-origin-when-cross-origin"
        assert headers["cache-control"] == "no-store, no-cache, must-revalidate"
        assert "permissions-policy" in headers

    def test_request_id_header(self, client: TestClient):
        resp = client.get("/api/v1/evidence/")
        assert "x-request-id" in resp.headers
        # Should be a UUID
        req_id = resp.headers["x-request-id"]
        assert len(req_id) == 36  # UUID format

    def test_request_ids_are_unique(self, client: TestClient):
        r1 = client.get("/health")
        r2 = client.get("/health")
        assert r1.headers["x-request-id"] != r2.headers["x-request-id"]

    def test_rate_limit_headers_present(self, client: TestClient):
        resp = client.get("/api/v1/evidence/")
        assert "x-ratelimit-limit" in resp.headers
        assert "x-ratelimit-remaining" in resp.headers

    def test_hsts_with_forwarded_proto(self, client: TestClient):
        resp = client.get("/health", headers={"X-Forwarded-Proto": "https"})
        assert "strict-transport-security" in resp.headers

    def test_no_hsts_without_tls(self, client: TestClient):
        resp = client.get("/health")
        assert "strict-transport-security" not in resp.headers
