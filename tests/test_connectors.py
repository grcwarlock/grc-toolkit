"""Tests for the connector framework and collector utilities."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime

import pytest

from modules.collectors.base import compute_hash, create_evidence, safe_collect
from modules.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorResult,
    IngestEvent,
    IngestStatus,
    SourceType,
)
from modules.connectors.cloud_adapter import CloudProviderConnector
from modules.models import NormalizedEvidence

# ---------------------------------------------------------------------------
# Mock connector for testing BaseConnector / ConnectorRegistry
# ---------------------------------------------------------------------------

class MockConnector(BaseConnector):
    def validate_config(self) -> list[str]:
        return []

    def collect(self) -> ConnectorResult:
        result = ConnectorResult(
            connector_name=self.config.name,
            status=IngestStatus.SUCCESS,
        )
        result.events.append(
            IngestEvent(
                source=self.config.name,
                provider=self.config.provider,
                data={"test": True},
                raw_data={"raw": True},
            )
        )
        result.complete()
        return result

    def health_check(self) -> bool:
        return True


class FailingConnector(BaseConnector):
    """Connector that always raises during collect()."""

    def validate_config(self) -> list[str]:
        return []

    def collect(self) -> ConnectorResult:
        raise RuntimeError("connection refused")

    def health_check(self) -> bool:
        return False


class InvalidConfigConnector(BaseConnector):
    """Connector whose validate_config always reports errors."""

    def validate_config(self) -> list[str]:
        return ["missing required setting: api_url"]

    def collect(self) -> ConnectorResult:
        return ConnectorResult(
            connector_name=self.config.name, status=IngestStatus.SUCCESS
        )

    def health_check(self) -> bool:
        return True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_config(**overrides) -> ConnectorConfig:
    defaults = {
        "name": "test-connector",
        "source_type": SourceType.CLOUD,
        "provider": "aws",
    }
    defaults.update(overrides)
    return ConnectorConfig(**defaults)


# ===========================================================================
# SourceType / IngestStatus enums
# ===========================================================================

class TestSourceType:
    def test_values(self):
        assert SourceType.CLOUD == "cloud"
        assert SourceType.SIEM == "siem"
        assert SourceType.EDR == "edr"
        assert SourceType.SCANNER == "scanner"
        assert SourceType.CSPM == "cspm"
        assert SourceType.IAM == "iam"
        assert SourceType.CUSTOM == "custom"

    def test_member_count(self):
        assert len(SourceType) == 7


class TestIngestStatus:
    def test_values(self):
        assert IngestStatus.SUCCESS == "success"
        assert IngestStatus.PARTIAL == "partial"
        assert IngestStatus.ERROR == "error"
        assert IngestStatus.TIMEOUT == "timeout"

    def test_member_count(self):
        assert len(IngestStatus) == 4


# ===========================================================================
# ConnectorConfig
# ===========================================================================

class TestConnectorConfig:
    def test_defaults(self):
        cfg = _make_config()
        assert cfg.enabled is True
        assert cfg.poll_interval_minutes == 60
        assert cfg.timeout_seconds == 30
        assert cfg.settings == {}
        assert cfg.secret_env_vars == []
        assert cfg.field_mapping == {}

    def test_custom_values(self):
        cfg = _make_config(
            enabled=False,
            poll_interval_minutes=5,
            timeout_seconds=120,
            settings={"endpoint": "https://example.com"},
            secret_env_vars=["API_KEY"],
            field_mapping={"src_field": "dst_field"},
        )
        assert cfg.enabled is False
        assert cfg.poll_interval_minutes == 5
        assert cfg.timeout_seconds == 120
        assert cfg.settings == {"endpoint": "https://example.com"}
        assert cfg.secret_env_vars == ["API_KEY"]
        assert cfg.field_mapping == {"src_field": "dst_field"}


# ===========================================================================
# IngestEvent
# ===========================================================================

class TestIngestEvent:
    def test_auto_id_generation(self):
        event = IngestEvent()
        assert event.event_id  # non-empty UUID
        assert len(event.event_id) == 36  # standard UUID length

    def test_custom_event_id_preserved(self):
        event = IngestEvent(event_id="my-custom-id")
        assert event.event_id == "my-custom-id"

    def test_hash_computed_with_raw_data(self):
        raw = {"key": "value"}
        event = IngestEvent(raw_data=raw)
        expected = hashlib.sha256(
            json.dumps(raw, sort_keys=True, default=str).encode()
        ).hexdigest()
        assert event.sha256_hash == expected

    def test_no_hash_without_raw_data(self):
        event = IngestEvent()
        assert event.sha256_hash == ""

    def test_default_severity(self):
        event = IngestEvent()
        assert event.severity == "info"

    def test_timestamp_auto_set(self):
        before = datetime.now(UTC)
        event = IngestEvent()
        after = datetime.now(UTC)
        assert before <= event.timestamp <= after


# ===========================================================================
# ConnectorResult
# ===========================================================================

class TestConnectorResult:
    def test_complete_success_no_errors(self):
        result = ConnectorResult(
            connector_name="test", status=IngestStatus.SUCCESS
        )
        result.events.append(IngestEvent(raw_data={"a": 1}))
        result.complete()
        assert result.status == IngestStatus.SUCCESS
        assert result.event_count == 1
        assert result.completed_at is not None
        assert result.duration_seconds >= 0.0

    def test_complete_partial_with_errors_and_events(self):
        result = ConnectorResult(
            connector_name="test", status=IngestStatus.SUCCESS
        )
        result.events.append(IngestEvent())
        result.errors.append("timeout on page 3")
        result.complete()
        assert result.status == IngestStatus.PARTIAL

    def test_complete_error_with_only_errors(self):
        result = ConnectorResult(
            connector_name="test", status=IngestStatus.SUCCESS
        )
        result.errors.append("auth failure")
        result.complete()
        assert result.status == IngestStatus.ERROR
        assert result.event_count == 0

    def test_complete_explicit_status_override(self):
        result = ConnectorResult(
            connector_name="test", status=IngestStatus.SUCCESS
        )
        result.errors.append("some error")
        result.events.append(IngestEvent())
        result.complete(status=IngestStatus.TIMEOUT)
        assert result.status == IngestStatus.TIMEOUT

    def test_duration_calculation(self):
        result = ConnectorResult(
            connector_name="test", status=IngestStatus.SUCCESS
        )
        result.complete()
        assert result.duration_seconds >= 0.0
        assert result.completed_at is not None
        assert result.completed_at >= result.started_at


# ===========================================================================
# BaseConnector — get_secret
# ===========================================================================

class TestBaseConnector:
    def test_get_secret_env_set(self, monkeypatch):
        monkeypatch.setenv("TEST_SECRET_KEY", "s3cret")
        connector = MockConnector(_make_config())
        assert connector.get_secret("TEST_SECRET_KEY") == "s3cret"

    def test_get_secret_env_unset(self, monkeypatch):
        monkeypatch.delenv("TEST_SECRET_KEY", raising=False)
        connector = MockConnector(_make_config())
        assert connector.get_secret("TEST_SECRET_KEY") == ""


# ===========================================================================
# ConnectorRegistry
# ===========================================================================

class TestConnectorRegistry:
    def test_register(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        assert "mock" in registry.list_types()

    def test_create_valid(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        cfg = _make_config(name="my-mock", provider="mock")
        connector = registry.create("mock", cfg)
        assert isinstance(connector, MockConnector)
        assert registry.get("my-mock") is connector

    def test_create_unknown_provider_raises(self):
        registry = ConnectorRegistry()
        cfg = _make_config(provider="nonexistent")
        with pytest.raises(ValueError, match="Unknown connector type"):
            registry.create("nonexistent", cfg)

    def test_create_invalid_config_raises(self):
        registry = ConnectorRegistry()
        registry.register("bad", InvalidConfigConnector)
        cfg = _make_config(provider="bad")
        with pytest.raises(ValueError, match="Invalid config"):
            registry.create("bad", cfg)

    def test_get_existing(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        cfg = _make_config(name="alpha", provider="mock")
        registry.create("mock", cfg)
        assert registry.get("alpha") is not None

    def test_get_nonexistent_returns_none(self):
        registry = ConnectorRegistry()
        assert registry.get("does-not-exist") is None

    def test_list_types(self):
        registry = ConnectorRegistry()
        registry.register("zulu", MockConnector)
        registry.register("alpha", MockConnector)
        assert registry.list_types() == ["alpha", "zulu"]

    def test_list_active(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        registry.create("mock", _make_config(name="beta", provider="mock"))
        registry.create("mock", _make_config(name="alpha", provider="mock"))
        assert registry.list_active() == ["alpha", "beta"]

    def test_collect_all_with_mixed_connectors(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        registry.create("mock", _make_config(name="c1", provider="mock"))
        registry.create("mock", _make_config(name="c2", provider="mock"))
        results = registry.collect_all()
        assert len(results) == 2
        assert all(r.status == IngestStatus.SUCCESS for r in results)

    def test_collect_all_skips_disabled(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        registry.create(
            "mock",
            _make_config(name="enabled-one", provider="mock", enabled=True),
        )
        registry.create(
            "mock",
            _make_config(name="disabled-one", provider="mock", enabled=False),
        )
        results = registry.collect_all()
        assert len(results) == 1
        assert results[0].connector_name == "enabled-one"

    def test_collect_all_handles_exceptions(self):
        registry = ConnectorRegistry()
        registry.register("mock", MockConnector)
        registry.register("fail", FailingConnector)
        registry.create("mock", _make_config(name="good", provider="mock"))
        registry.create("fail", _make_config(name="bad", provider="fail"))
        results = registry.collect_all()
        assert len(results) == 2
        names = {r.connector_name for r in results}
        assert names == {"good", "bad"}
        bad_result = next(r for r in results if r.connector_name == "bad")
        assert bad_result.status == IngestStatus.ERROR
        assert len(bad_result.errors) == 1
        assert "connection refused" in bad_result.errors[0]


# ===========================================================================
# CloudProviderConnector — validate_config only
# ===========================================================================

class TestCloudProviderConnector:
    @pytest.mark.parametrize("provider", ["aws", "azure", "gcp"])
    def test_validate_config_valid_providers(self, provider):
        cfg = _make_config(provider=provider, source_type=SourceType.CLOUD)
        connector = CloudProviderConnector(cfg)
        assert connector.validate_config() == []

    def test_validate_config_invalid_provider(self):
        cfg = _make_config(provider="digitalocean", source_type=SourceType.CLOUD)
        connector = CloudProviderConnector(cfg)
        errors = connector.validate_config()
        assert len(errors) == 1
        assert "Unsupported cloud provider" in errors[0]


# ===========================================================================
# collectors/base.py — create_evidence, safe_collect, compute_hash
# ===========================================================================

class TestCreateEvidence:
    def test_returns_normalized_evidence(self):
        evidence = create_evidence(
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
            resource_type="iam_user",
            region="us-east-1",
            account_id="123456789012",
            data={"Users": [{"UserName": "alice"}]},
            normalized_data={"users": ["alice"]},
            status="collected",
        )
        assert isinstance(evidence, NormalizedEvidence)
        assert evidence.control_id == "AC-2"
        assert evidence.check_id == "AC-2.a"
        assert evidence.provider == "aws"
        assert evidence.service == "iam"
        assert evidence.resource_type == "iam_user"
        assert evidence.region == "us-east-1"
        assert evidence.account_id == "123456789012"
        assert evidence.status == "collected"
        assert evidence.evidence_id  # auto-generated


class TestSafeCollect:
    def test_returns_result_on_success(self):
        expected = create_evidence(
            control_id="SC-7",
            check_id="SC-7.a",
            provider="aws",
            service="ec2",
            resource_type="security_group",
            region="us-west-2",
            account_id="111111111111",
            data={"sg": "data"},
            normalized_data={"sg": "normalized"},
        )
        result = safe_collect(
            func=lambda: expected,
            control_id="SC-7",
            check_id="SC-7.a",
            provider="aws",
            service="ec2",
            region="us-west-2",
            account_id="111111111111",
        )
        assert result is expected

    def test_returns_error_evidence_on_exception(self):
        def boom():
            raise RuntimeError("API rate limit exceeded")

        result = safe_collect(
            func=boom,
            control_id="AC-2",
            check_id="AC-2.a",
            provider="aws",
            service="iam",
            region="us-east-1",
            account_id="123456789012",
        )
        assert isinstance(result, NormalizedEvidence)
        assert result.status == "error"
        assert "API rate limit exceeded" in result.error_message


class TestComputeHash:
    def test_deterministic(self):
        data = {"b": 2, "a": 1}
        h1 = compute_hash(data)
        h2 = compute_hash(data)
        assert h1 == h2
        assert len(h1) == 64  # SHA-256 hex digest length

    def test_different_data_different_hash(self):
        h1 = compute_hash({"key": "value1"})
        h2 = compute_hash({"key": "value2"})
        assert h1 != h2
