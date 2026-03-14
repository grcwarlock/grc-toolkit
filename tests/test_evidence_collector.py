from __future__ import annotations

import json

from modules.evidence_collector import (
    EvidenceArtifact,
    EvidenceStore,
    load_framework_checks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

FRAMEWORK_PATH = "config/frameworks.yaml"


def _make_artifact(**overrides) -> EvidenceArtifact:
    defaults = dict(
        control_id="AC-2",
        check_id="AC-2.a",
        provider="aws",
        service="iam",
        method="list_users",
        region="us-east-1",
        collected_at="2026-01-01T00:00:00Z",
        data={"Users": [{"UserName": "alice"}]},
    )
    defaults.update(overrides)
    return EvidenceArtifact(**defaults)


# ===================================================================
# EvidenceArtifact tests
# ===================================================================


class TestEvidenceArtifact:
    def test_create_with_all_fields(self):
        artifact = EvidenceArtifact(
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
            method="list_users",
            region="us-east-1",
            collected_at="2026-01-01T00:00:00Z",
            data={"Users": []},
            status="error",
            error_message="boom",
            metadata={"account_id": "123456789012"},
        )
        assert artifact.control_id == "AC-2"
        assert artifact.status == "error"
        assert artifact.error_message == "boom"
        assert artifact.metadata == {"account_id": "123456789012"}

    def test_default_status_is_collected(self):
        artifact = _make_artifact()
        assert artifact.status == "collected"

    def test_default_metadata_is_empty_dict(self):
        artifact = _make_artifact()
        assert artifact.metadata == {}

    def test_default_error_message_is_empty_string(self):
        artifact = _make_artifact()
        assert artifact.error_message == ""

    def test_to_dict_returns_dict(self):
        artifact = _make_artifact()
        result = artifact.to_dict()
        assert isinstance(result, dict)

    def test_to_dict_contains_all_fields(self):
        artifact = _make_artifact()
        d = artifact.to_dict()
        expected_keys = {
            "control_id", "check_id", "provider", "service", "method",
            "region", "collected_at", "data", "status", "error_message",
            "metadata",
        }
        assert set(d.keys()) == expected_keys

    def test_to_dict_is_json_serializable(self):
        artifact = _make_artifact(metadata={"nested": {"key": "value"}})
        d = artifact.to_dict()
        serialized = json.dumps(d)
        assert isinstance(serialized, str)

    def test_to_dict_roundtrip(self):
        artifact = _make_artifact(status="error", error_message="fail")
        d = artifact.to_dict()
        restored = EvidenceArtifact(**d)
        assert restored == artifact


# ===================================================================
# EvidenceStore tests
# ===================================================================


class TestEvidenceStore:
    def test_save_creates_run_directory(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="run-001")
        assert run_dir.is_dir()

    def test_save_creates_manifest(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="run-001")
        manifest_path = run_dir / "manifest.json"
        assert manifest_path.exists()

    def test_save_creates_artifact_json_files(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="run-001")
        expected_file = run_dir / "AC-2.a_aws_us-east-1.json"
        assert expected_file.exists()

    def test_save_manifest_has_correct_artifact_count(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifacts = [
            _make_artifact(check_id="AC-2.a"),
            _make_artifact(check_id="AC-2.d", region="eu-west-1"),
        ]
        run_dir = store.save(artifacts, run_id="run-002")
        with open(run_dir / "manifest.json") as f:
            manifest = json.load(f)
        assert manifest["artifact_count"] == 2
        assert len(manifest["artifacts"]) == 2

    def test_save_manifest_entries_have_required_keys(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="run-003")
        with open(run_dir / "manifest.json") as f:
            manifest = json.load(f)
        entry = manifest["artifacts"][0]
        assert "file" in entry
        assert "control_id" in entry
        assert "check_id" in entry
        assert "status" in entry

    def test_save_with_custom_run_id(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="my-custom-run")
        assert run_dir.name == "my-custom-run"

    def test_save_with_empty_run_id_generates_timestamp(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        run_dir = store.save([artifact], run_id="")
        # Generated ID is like "20260101_120000" (YYYYMMDD_HHMMSS)
        assert len(run_dir.name) == 15
        assert "_" in run_dir.name

    def test_load_run_recovers_artifacts(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        store.save([artifact], run_id="run-load")
        loaded = store.load_run("run-load")
        assert len(loaded) == 1

    def test_load_run_artifacts_match_originals(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        original = _make_artifact(
            status="error",
            error_message="timeout",
            metadata={"account_id": "111"},
        )
        store.save([original], run_id="run-match")
        loaded = store.load_run("run-match")
        assert loaded[0].control_id == original.control_id
        assert loaded[0].check_id == original.check_id
        assert loaded[0].provider == original.provider
        assert loaded[0].service == original.service
        assert loaded[0].method == original.method
        assert loaded[0].region == original.region
        assert loaded[0].data == original.data
        assert loaded[0].status == original.status
        assert loaded[0].error_message == original.error_message
        assert loaded[0].metadata == original.metadata

    def test_save_load_roundtrip_multiple_artifacts(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifacts = [
            _make_artifact(check_id="AC-2.a", region="us-east-1"),
            _make_artifact(check_id="AC-6.1", region="eu-west-1", data={"Policies": []}),
            _make_artifact(check_id="AU-2.a", region="ap-southeast-1", status="error"),
        ]
        store.save(artifacts, run_id="run-multi")
        loaded = store.load_run("run-multi")
        assert len(loaded) == 3
        loaded_ids = {a.check_id for a in loaded}
        assert loaded_ids == {"AC-2.a", "AC-6.1", "AU-2.a"}

    def test_list_runs_returns_all_saved_runs(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        artifact = _make_artifact()
        store.save([artifact], run_id="run-alpha")
        store.save([artifact], run_id="run-beta")
        runs = store.list_runs()
        run_ids = {r["run_id"] for r in runs}
        assert run_ids == {"run-alpha", "run-beta"}

    def test_list_runs_empty_directory(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        runs = store.list_runs()
        assert runs == []

    def test_list_runs_entries_have_expected_keys(self, tmp_path):
        store = EvidenceStore(str(tmp_path))
        store.save([_make_artifact()], run_id="run-keys")
        runs = store.list_runs()
        assert len(runs) == 1
        run = runs[0]
        assert "run_id" in run
        assert "collected_at" in run
        assert "artifact_count" in run


# ===================================================================
# load_framework_checks tests
# ===================================================================


class TestLoadFrameworkChecks:
    def test_loads_from_actual_yaml(self):
        checks = load_framework_checks(FRAMEWORK_PATH)
        assert isinstance(checks, list)
        assert len(checks) > 0

    def test_default_framework_is_nist_800_53(self):
        checks = load_framework_checks(FRAMEWORK_PATH)
        # All checks should come from nist_800_53; spot-check a known control
        control_ids = {c["control_id"] for c in checks}
        assert "AC-2" in control_ids

    def test_each_check_has_required_keys(self):
        checks = load_framework_checks(FRAMEWORK_PATH)
        required_keys = {"control_id", "check_id", "provider", "service", "method", "assertion"}
        for check in checks:
            assert required_keys.issubset(check.keys()), (
                f"Missing keys in check: {required_keys - set(check.keys())}"
            )

    def test_filter_by_control_family_ac(self):
        checks = load_framework_checks(FRAMEWORK_PATH, control_family="AC")
        assert len(checks) > 0
        for check in checks:
            assert check["control_id"].startswith("AC-")

    def test_filter_by_nonexistent_family_returns_empty(self):
        checks = load_framework_checks(FRAMEWORK_PATH, control_family="ZZ")
        assert checks == []

    def test_checks_include_multiple_providers(self):
        checks = load_framework_checks(FRAMEWORK_PATH)
        providers = {c["provider"] for c in checks}
        # The frameworks.yaml has at least aws
        assert "aws" in providers
