"""
Base connector framework for multi-source telemetry ingestion.

Provides a unified adapter interface that supports:
- Cloud providers (AWS, Azure, GCP) via existing collectors
- SIEM platforms (Splunk, Sentinel, QRadar)
- EDR tools (CrowdStrike, SentinelOne, Carbon Black)
- Vulnerability scanners (Tenable, Qualys, Rapid7)
- Custom sources via webhook or polling

Each connector normalizes its data into IngestEvent objects that map
to the GRC Toolkit's NormalizedEvidence model.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

logger = logging.getLogger(__name__)


class SourceType(StrEnum):
    """Categories of data sources."""
    CLOUD = "cloud"
    SIEM = "siem"
    EDR = "edr"
    SCANNER = "scanner"
    CSPM = "cspm"
    IAM = "iam"
    CUSTOM = "custom"


class IngestStatus(StrEnum):
    SUCCESS = "success"
    PARTIAL = "partial"
    ERROR = "error"
    TIMEOUT = "timeout"


@dataclass
class ConnectorConfig:
    """Configuration for a data source connector.

    Secrets (API keys, passwords) should be referenced by env var name,
    NOT stored directly.
    """
    name: str
    source_type: SourceType
    provider: str  # e.g., "splunk", "crowdstrike", "tenable"
    enabled: bool = True
    poll_interval_minutes: int = 60
    timeout_seconds: int = 30
    # Non-secret config (endpoints, project IDs, etc.)
    settings: dict[str, Any] = field(default_factory=dict)
    # Names of env vars that hold secrets
    secret_env_vars: list[str] = field(default_factory=list)
    # Field mapping: source field name -> normalized field name
    field_mapping: dict[str, str] = field(default_factory=dict)


@dataclass
class IngestEvent:
    """A single normalized telemetry event from any source.

    This is the canonical event format that all connectors produce.
    It maps directly to NormalizedEvidence for storage.
    """
    event_id: str = ""
    source: str = ""              # connector name
    source_type: str = ""         # cloud, siem, edr, scanner, etc.
    provider: str = ""            # aws, splunk, crowdstrike, etc.
    event_type: str = ""          # e.g., "iam_user", "alert", "vulnerability"
    severity: str = "info"        # critical, high, medium, low, info
    timestamp: datetime = field(default_factory=lambda: datetime.now(UTC))

    # Resource identification
    resource_id: str = ""
    resource_type: str = ""
    region: str = ""
    account_id: str = ""

    # Normalized data payload
    data: dict = field(default_factory=dict)
    raw_data: dict = field(default_factory=dict)

    # GRC mapping
    control_ids: list[str] = field(default_factory=list)  # Mapped framework controls
    tags: dict[str, str] = field(default_factory=dict)

    # Integrity
    sha256_hash: str = ""

    def __post_init__(self):
        if not self.event_id:
            self.event_id = str(uuid.uuid4())
        if not self.sha256_hash and self.raw_data:
            self._compute_hash()

    def _compute_hash(self) -> None:
        serialized = json.dumps(self.raw_data, sort_keys=True, default=str).encode()
        self.sha256_hash = hashlib.sha256(serialized).hexdigest()


@dataclass
class ConnectorResult:
    """Result of a connector sync operation."""
    connector_name: str
    status: IngestStatus
    events: list[IngestEvent] = field(default_factory=list)
    event_count: int = 0
    errors: list[str] = field(default_factory=list)
    started_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    completed_at: datetime | None = None
    duration_seconds: float = 0.0

    def complete(self, status: IngestStatus | None = None) -> None:
        self.completed_at = datetime.now(UTC)
        self.duration_seconds = (
            self.completed_at - self.started_at
        ).total_seconds()
        self.event_count = len(self.events)
        if status:
            self.status = status
        elif self.errors and self.events:
            self.status = IngestStatus.PARTIAL
        elif self.errors:
            self.status = IngestStatus.ERROR
        else:
            self.status = IngestStatus.SUCCESS


class BaseConnector(ABC):
    """Abstract base class for all data source connectors.

    Subclass this to integrate a new data source. Implement:
    - validate_config(): verify configuration and connectivity
    - collect(): fetch and normalize data into IngestEvent objects
    - health_check(): verify the source is reachable

    Example for a Splunk connector:

        class SplunkConnector(BaseConnector):
            def collect(self) -> ConnectorResult:
                result = ConnectorResult(connector_name=self.config.name, status=IngestStatus.SUCCESS)
                # ... fetch saved search results from Splunk ...
                for event in splunk_events:
                    result.events.append(IngestEvent(
                        source=self.config.name,
                        source_type="siem",
                        provider="splunk",
                        event_type="security_alert",
                        data=normalize_splunk_event(event),
                        raw_data=event,
                    ))
                result.complete()
                return result
    """

    def __init__(self, config: ConnectorConfig):
        self.config = config
        self.logger = logging.getLogger(f"connector.{config.name}")

    @abstractmethod
    def validate_config(self) -> list[str]:
        """Validate connector configuration. Return list of error messages (empty = valid)."""
        ...

    @abstractmethod
    def collect(self) -> ConnectorResult:
        """Fetch data from the source and return normalized events."""
        ...

    @abstractmethod
    def health_check(self) -> bool:
        """Check if the data source is reachable and credentials are valid."""
        ...

    def get_secret(self, env_var: str) -> str:
        """Safely retrieve a secret from environment variables."""
        import os
        value = os.environ.get(env_var, "")
        if not value:
            self.logger.warning("Secret env var %s is not set", env_var)
        return value


class ConnectorRegistry:
    """Registry of available connector types and active instances.

    Usage:
        registry = ConnectorRegistry()
        registry.register("splunk", SplunkConnector)
        connector = registry.create("splunk", config)
        result = connector.collect()
    """

    def __init__(self):
        self._connector_types: dict[str, type[BaseConnector]] = {}
        self._active: dict[str, BaseConnector] = {}

    def register(self, provider: str, connector_class: type[BaseConnector]) -> None:
        """Register a connector type."""
        self._connector_types[provider] = connector_class
        logger.info("Registered connector type: %s", provider)

    def create(self, provider: str, config: ConnectorConfig) -> BaseConnector:
        """Create and register an active connector instance."""
        if provider not in self._connector_types:
            raise ValueError(
                f"Unknown connector type: {provider}. "
                f"Available: {sorted(self._connector_types)}"
            )
        connector = self._connector_types[provider](config)
        errors = connector.validate_config()
        if errors:
            raise ValueError(f"Invalid config for {provider}: {errors}")
        self._active[config.name] = connector
        return connector

    def get(self, name: str) -> BaseConnector | None:
        """Get an active connector by name."""
        return self._active.get(name)

    def list_types(self) -> list[str]:
        """List registered connector types."""
        return sorted(self._connector_types)

    def list_active(self) -> list[str]:
        """List names of active connector instances."""
        return sorted(self._active)

    def collect_all(self) -> list[ConnectorResult]:
        """Run collection on all active connectors."""
        results = []
        for name, connector in self._active.items():
            if not connector.config.enabled:
                continue
            try:
                result = connector.collect()
                results.append(result)
                logger.info(
                    "Connector %s: %d events, status=%s",
                    name, result.event_count, result.status,
                )
            except Exception as e:
                logger.error("Connector %s failed: %s", name, e)
                results.append(ConnectorResult(
                    connector_name=name,
                    status=IngestStatus.ERROR,
                    errors=[str(e)],
                ))
        return results
