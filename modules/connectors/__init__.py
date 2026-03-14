"""
Connector framework for integrating external data sources.

Provides a unified interface for ingesting telemetry from cloud providers,
SIEM platforms, EDR tools, vulnerability scanners, and other security tools
into the GRC Toolkit's normalized evidence model.
"""

from modules.connectors.base import (
    BaseConnector,
    ConnectorConfig,
    ConnectorRegistry,
    ConnectorResult,
    IngestEvent,
)

__all__ = [
    "BaseConnector",
    "ConnectorConfig",
    "ConnectorRegistry",
    "ConnectorResult",
    "IngestEvent",
]
