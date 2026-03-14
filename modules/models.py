"""
Core data models for the GRC platform.

Provider-agnostic evidence, assessment, and compliance models that
decouple business logic from cloud provider API specifics. All
collectors produce NormalizedEvidence; all assertions consume it.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Protocol

# ── Enums ─────────────────────────────────────────────────────────────

class ComplianceStatus(StrEnum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_ASSESSED = "not_assessed"
    NOT_APPLICABLE = "not_applicable"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ── NormalizedEvidence ────────────────────────────────────────────────

@dataclass
class NormalizedEvidence:
    """Provider-agnostic evidence artifact with integrity guarantees.

    Every collector — AWS, Azure, GCP — produces these. The `data` field
    holds the raw API response for audit trail. The `normalized_data`
    field holds the provider-agnostic structure that assertions evaluate.
    """

    control_id: str
    check_id: str
    provider: str                       # "aws", "azure", "gcp"
    service: str                        # normalized service name
    resource_type: str = ""             # e.g., "iam_user", "security_group"
    region: str = ""
    account_id: str = ""                # AWS account, Azure subscription, GCP project
    data: dict = field(default_factory=dict)
    normalized_data: dict = field(default_factory=dict)
    status: str = "collected"           # collected, error, timeout
    error_message: str = ""
    metadata: dict = field(default_factory=dict)
    ttl_days: int = 365

    # Auto-populated
    evidence_id: str = ""
    collected_at: datetime = field(default_factory=lambda: datetime.now(UTC))
    sha256_hash: str = ""

    def __post_init__(self):
        if not self.evidence_id:
            self.evidence_id = str(uuid.uuid4())
        if not self.sha256_hash:
            self.compute_hash()

    def compute_hash(self) -> str:
        """Compute SHA-256 of the raw evidence data for integrity verification."""
        serialized = json.dumps(self.data, sort_keys=True, default=str).encode()
        self.sha256_hash = hashlib.sha256(serialized).hexdigest()
        return self.sha256_hash

    def verify_integrity(self) -> bool:
        """Re-compute hash and compare against stored value."""
        serialized = json.dumps(self.data, sort_keys=True, default=str).encode()
        computed = hashlib.sha256(serialized).hexdigest()
        return computed == self.sha256_hash

    def to_dict(self) -> dict:
        d = asdict(self)
        d["collected_at"] = self.collected_at.isoformat()
        return d


# ── AssessmentResult (enhanced) ───────────────────────────────────────

@dataclass
class AssessmentResult:
    """Result of evaluating a control check against evidence."""

    control_id: str
    check_id: str
    assertion: str
    status: str                         # pass, fail, error, not_assessed
    provider: str
    region: str
    severity: str = "medium"
    findings: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    evidence_summary: str = ""
    remediation: str = ""
    assessor: str = "python"            # "opa", "python", "manual"
    policy_id: str = ""                 # OPA policy ID if applicable

    # Auto-populated
    result_id: str = ""
    assessed_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    def __post_init__(self):
        if not self.result_id:
            self.result_id = str(uuid.uuid4())

    def to_dict(self) -> dict:
        d = asdict(self)
        d["assessed_at"] = self.assessed_at.isoformat()
        return d


# ── CloudCollector Protocol ───────────────────────────────────────────

class CloudCollector(Protocol):
    """Interface that all cloud collectors must implement.

    Each method returns normalized evidence that can be assessed
    against framework controls regardless of the source provider.
    """

    provider: str

    def collect_identity_inventory(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def collect_network_boundaries(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def collect_audit_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def collect_encryption_status(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def collect_logging_configuration(
        self, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def collect_by_service(
        self, service: str, method: str, control_id: str, check_id: str
    ) -> list[NormalizedEvidence]: ...

    def get_account_id(self) -> str: ...


# ── ResourceNormalizer ────────────────────────────────────────────────

class ResourceNormalizer:
    """Maps provider-specific API responses to normalized structures.

    This is the key abstraction that allows assertions to be written
    once and evaluate evidence from any cloud provider.
    """

    @staticmethod
    def normalize_iam_users(provider: str, raw_data: dict) -> dict:
        """Normalize identity inventory across providers."""
        if provider == "aws":
            users = []
            for user in raw_data.get("Users", []):
                users.append({
                    "username": user.get("UserName", ""),
                    "mfa_enabled": bool(user.get("MFADevices")),
                    "access_keys": [
                        {
                            "key_id": k.get("AccessKeyId", ""),
                            "status": k.get("Status", ""),
                            "last_used_days": 0,
                        }
                        for k in user.get("AccessKeyMetadata", [])
                    ],
                    "last_activity": user.get("PasswordLastUsed", ""),
                    "groups": [g.get("GroupName", "") for g in user.get("Groups", [])],
                    "policies": [],
                })
            summary = raw_data.get("SummaryMap", {})
            return {
                "users": users,
                "root_account": {
                    "access_keys_present": summary.get("AccountAccessKeysPresent", 0) > 0,
                    "mfa_enabled": summary.get("AccountMFAEnabled", 0) > 0,
                },
                "total_users": len(users),
                "service_accounts": [],
            }

        if provider == "azure":
            users = []
            for user in raw_data.get("users", []):
                users.append({
                    "username": user.get("userPrincipalName", ""),
                    "mfa_enabled": user.get("mfa_registered", False),
                    "access_keys": [],
                    "last_activity": user.get("lastSignInDateTime", ""),
                    "groups": user.get("groups", []),
                    "policies": [],
                })
            return {
                "users": users,
                "root_account": {"access_keys_present": False, "mfa_enabled": True},
                "total_users": len(users),
                "service_accounts": [
                    {"name": sp.get("displayName", ""), "email": sp.get("appId", ""),
                     "keys": sp.get("credentials", []), "last_used": ""}
                    for sp in raw_data.get("service_principals", [])
                ],
            }

        if provider == "gcp":
            service_accounts = []
            for sa in raw_data.get("service_accounts", []):
                service_accounts.append({
                    "name": sa.get("displayName", ""),
                    "email": sa.get("email", ""),
                    "keys": sa.get("keys", []),
                    "last_used": "",
                })
            return {
                "users": [],
                "root_account": {"access_keys_present": False, "mfa_enabled": True},
                "total_users": 0,
                "service_accounts": service_accounts,
            }

        return {"users": [], "root_account": {}, "total_users": 0, "service_accounts": []}

    @staticmethod
    def normalize_security_groups(provider: str, raw_data: dict) -> dict:
        """Normalize network security rules across providers."""
        rules = []

        if provider == "aws":
            for sg in raw_data.get("SecurityGroups", []):
                sg_id = sg.get("GroupId", "")
                sg_name = sg.get("GroupName", "")
                for perm in sg.get("IpPermissions", []):
                    from_port = perm.get("FromPort", 0)
                    to_port = perm.get("ToPort", 65535)
                    protocol = perm.get("IpProtocol", "-1")
                    for ip in perm.get("IpRanges", []):
                        rules.append({
                            "group_id": sg_id, "group_name": sg_name,
                            "direction": "inbound", "protocol": protocol,
                            "port_range": [from_port, to_port],
                            "source": ip.get("CidrIp", ""),
                            "description": ip.get("Description", ""),
                        })
                    for ip in perm.get("Ipv6Ranges", []):
                        rules.append({
                            "group_id": sg_id, "group_name": sg_name,
                            "direction": "inbound", "protocol": protocol,
                            "port_range": [from_port, to_port],
                            "source": ip.get("CidrIpv6", ""),
                            "description": ip.get("Description", ""),
                        })
            nacls = raw_data.get("NetworkAcls", [])
            default_deny = all(
                any(
                    e.get("RuleNumber") == 32767
                    and not e.get("Egress", True)
                    and e.get("RuleAction") == "deny"
                    for e in nacl.get("Entries", [])
                )
                for nacl in nacls
            ) if nacls else False

        elif provider == "azure":
            for nsg in raw_data.get("network_security_groups", []):
                nsg_id = nsg.get("id", "")
                nsg_name = nsg.get("name", "")
                for rule in nsg.get("security_rules", []):
                    rules.append({
                        "group_id": nsg_id, "group_name": nsg_name,
                        "direction": "inbound" if rule.get("direction") == "Inbound" else "outbound",
                        "protocol": rule.get("protocol", "*"),
                        "port_range": [
                            int(rule.get("destination_port_range", "0").split("-")[0]),
                            int(rule.get("destination_port_range", "65535").split("-")[-1]),
                        ] if rule.get("destination_port_range", "*") != "*" else [0, 65535],
                        "source": rule.get("source_address_prefix", ""),
                        "description": rule.get("description", ""),
                    })
            default_deny = True  # Azure NSGs default deny

        elif provider == "gcp":
            for rule in raw_data.get("firewall_rules", []):
                direction = "inbound" if rule.get("direction") == "INGRESS" else "outbound"
                for allowed in rule.get("allowed", []):
                    for port_str in allowed.get("ports", ["0-65535"]):
                        parts = str(port_str).split("-")
                        port_range = [int(parts[0]), int(parts[-1])]
                        for src in rule.get("sourceRanges", [""]):
                            rules.append({
                                "group_id": rule.get("id", ""),
                                "group_name": rule.get("name", ""),
                                "direction": direction,
                                "protocol": allowed.get("IPProtocol", "all"),
                                "port_range": port_range,
                                "source": src,
                                "description": rule.get("description", ""),
                            })
            default_deny = True  # GCP implied deny
        else:
            default_deny = False

        return {
            "rules": rules,
            "total_groups": len(set(r["group_id"] for r in rules)) if rules else 0,
            "default_deny_inbound": default_deny,
        }

    @staticmethod
    def normalize_audit_config(provider: str, raw_data: dict) -> dict:
        """Normalize audit/logging configuration across providers."""
        if provider == "aws":
            trails = []
            for trail in raw_data.get("trailList", raw_data.get("Trails", [])):
                trails.append({
                    "name": trail.get("Name", ""),
                    "is_multi_region": trail.get("IsMultiRegionTrail", False),
                    "is_logging": trail.get("IsLogging", False),
                    "log_file_validation_enabled": trail.get("LogFileValidationEnabled", False),
                    "s3_bucket": trail.get("S3BucketName", ""),
                })
            return {
                "trails": trails,
                "activity_log_enabled": False,
                "audit_logging_enabled": len(trails) > 0,
            }

        if provider == "azure":
            return {
                "trails": [],
                "activity_log_enabled": raw_data.get("activity_log_enabled", False),
                "audit_logging_enabled": raw_data.get("activity_log_enabled", False),
            }

        if provider == "gcp":
            return {
                "trails": [],
                "activity_log_enabled": False,
                "audit_logging_enabled": raw_data.get("audit_logging_enabled", False),
            }

        return {"trails": [], "activity_log_enabled": False, "audit_logging_enabled": False}

    @staticmethod
    def normalize_encryption(provider: str, raw_data: dict) -> dict:
        """Normalize encryption status across providers."""
        resources = []
        for item in raw_data.get("resources", []):
            resources.append({
                "resource_id": item.get("id", ""),
                "resource_type": item.get("type", ""),
                "encrypted": item.get("encrypted", False),
                "encryption_type": item.get("encryption_type", "none"),
                "key_id": item.get("key_id", ""),
            })
        return {
            "resources": resources,
            "total_resources": len(resources),
            "encrypted_count": sum(1 for r in resources if r["encrypted"]),
        }


# ── FrameworkCrosswalk ────────────────────────────────────────────────

class FrameworkCrosswalk:
    """Maps controls between compliance frameworks.

    Enables evidence reuse: collect once for NIST, automatically
    satisfy overlapping SOC 2, ISO 27001, and CMMC requirements.
    """

    def __init__(self, crosswalk_data: dict):
        self._data = crosswalk_data

    @classmethod
    def load_from_yaml(cls, path: str) -> FrameworkCrosswalk:
        import yaml
        with open(path) as f:
            data = yaml.safe_load(f)
        return cls(data.get("crosswalks", data))

    def map_control(
        self, source_framework: str, control_id: str, target_framework: str
    ) -> list[dict]:
        """Map a control from source to target framework."""
        for key, crosswalk in self._data.items():
            src = crosswalk.get("source", "")
            tgt = crosswalk.get("target", "")
            if src == source_framework and tgt == target_framework:
                mappings = crosswalk.get("mappings", {})
                return mappings.get(control_id, [])
        return []

    def get_shared_evidence(self, control_id: str) -> list[dict]:
        """Find all framework controls that share evidence with a given control."""
        shared = []
        for key, crosswalk in self._data.items():
            mappings = crosswalk.get("mappings", {})
            if control_id in mappings:
                for target in mappings[control_id]:
                    shared.append({
                        "framework": crosswalk.get("target", key),
                        "control": target.get("control", ""),
                        "confidence": target.get("confidence", "unknown"),
                    })
        return shared

    def list_frameworks(self) -> list[str]:
        """List all frameworks referenced in crosswalks."""
        frameworks = set()
        for crosswalk in self._data.values():
            frameworks.add(crosswalk.get("source", ""))
            frameworks.add(crosswalk.get("target", ""))
        return sorted(frameworks - {""})
