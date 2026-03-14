"""
control_assessor.py
Evaluates collected evidence against codified control assertions.

Takes the raw evidence from the collector and runs it through
assertion logic to produce pass/fail/error results for each
control check. Think of this as the "brain" that decides whether
your environment actually meets the control requirement.
"""

import logging
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class AssessmentResult:
    """Result of evaluating a single control check against collected evidence."""
    control_id: str
    check_id: str
    assertion: str
    status: str  # pass, fail, error, not_assessed
    provider: str
    region: str
    findings: list[str] = field(default_factory=list)
    evidence_summary: str = ""
    assessed_at: str = ""
    remediation: str = ""

    def __post_init__(self):
        if not self.assessed_at:
            self.assessed_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    def to_dict(self) -> dict:
        return asdict(self)


class AssertionEngine:
    """
    Registry of assertion functions mapped to assertion names from the framework YAML.

    Each assertion takes the raw API response data and returns a tuple of
    (passed: bool, findings: list[str]). Findings explain what was checked
    and what failed, giving auditors the detail they need.

    To add a new assertion, decorate a method with @assertion("name").
    """

    def __init__(self):
        self._assertions: dict[str, Callable] = {}
        self._register_defaults()

    def register(self, name: str):
        """Decorator to register an assertion function."""
        def decorator(func):
            self._assertions[name] = func
            return func
        return decorator

    def evaluate(self, assertion_name: str, data: Any,
                 control_id: str, check_id: str,
                 provider: str, region: str) -> AssessmentResult:
        """Run a named assertion against evidence data."""
        if assertion_name not in self._assertions:
            return AssessmentResult(
                control_id=control_id, check_id=check_id,
                assertion=assertion_name, status="error",
                provider=provider, region=region,
                findings=[f"No assertion function registered for '{assertion_name}'"],
            )

        if data is None:
            return AssessmentResult(
                control_id=control_id, check_id=check_id,
                assertion=assertion_name, status="error",
                provider=provider, region=region,
                findings=["No evidence data available (collection may have failed)"],
            )

        try:
            passed, findings = self._assertions[assertion_name](data)
            return AssessmentResult(
                control_id=control_id, check_id=check_id,
                assertion=assertion_name,
                status="pass" if passed else "fail",
                provider=provider, region=region,
                findings=findings,
            )
        except Exception as e:
            logger.error("Assertion '%s' raised an exception: %s", assertion_name, e)
            return AssessmentResult(
                control_id=control_id, check_id=check_id,
                assertion=assertion_name, status="error",
                provider=provider, region=region,
                findings=[f"Assertion raised exception: {str(e)}"],
            )

    def _register_defaults(self):
        """Register all the built-in assertion functions."""

        # === Access Control Assertions ===

        @self.register("all_users_have_mfa")
        def check_mfa(data):
            """Verify all IAM users have MFA enabled."""
            findings = []
            users_without_mfa = []

            # Handle paginated list_users response
            user_list = _extract_key(data, "Users", [])

            for user in user_list:
                username = user.get("UserName", "unknown")
                # In a real implementation, you'd make an additional API call
                # to list_mfa_devices for each user. For the framework, we
                # check if MFA serial is present in the user metadata.
                if not user.get("MFADevices") and username != "root":
                    users_without_mfa.append(username)

            if users_without_mfa:
                findings.append(
                    f"Users without MFA enabled: {', '.join(users_without_mfa)}"
                )
                findings.append(
                    f"{len(users_without_mfa)} of {len(user_list)} users lack MFA"
                )
                return False, findings

            findings.append(f"All {len(user_list)} IAM users have MFA enabled")
            return True, findings

        @self.register("no_root_access_keys")
        def check_root_keys(data):
            """Verify no access keys exist for the root account."""
            findings = []
            summary = _extract_key(data, "SummaryMap", {})

            root_keys = summary.get("AccountAccessKeysPresent", 0)
            if root_keys > 0:
                findings.append(f"Root account has {root_keys} active access key(s)")
                findings.append("REMEDIATION: Delete root access keys immediately")
                return False, findings

            findings.append("No root account access keys present")
            return True, findings

        @self.register("no_wildcard_admin_policies")
        def check_wildcard_policies(data):
            """Check for overly permissive IAM policies with wildcard actions/resources."""
            findings = []
            violations = []

            policies = _extract_key(data, "Policies", [])
            for policy in policies:
                policy_name = policy.get("PolicyName", "unknown")
                # Flag policies with "Admin" or "FullAccess" in the name
                # as candidates for review (real implementation would
                # inspect the actual policy document)
                if any(term in policy_name for term in ["AdministratorAccess", "FullAccess"]):
                    if not policy.get("IsAWSManaged", True):
                        violations.append(policy_name)

            if violations:
                findings.append(f"Custom policies with broad access: {', '.join(violations)}")
                return False, findings

            findings.append("No custom wildcard admin policies detected")
            return True, findings

        # === Audit and Accountability Assertions ===

        @self.register("cloudtrail_enabled_all_regions")
        def check_cloudtrail(data):
            """Verify CloudTrail is enabled in all regions."""
            findings = []
            trails = _extract_key(data, "trailList", [])

            if not trails:
                findings.append("No CloudTrail trails configured")
                return False, findings

            multi_region_trails = [
                t for t in trails if t.get("IsMultiRegionTrail", False)
            ]

            if not multi_region_trails:
                findings.append("No multi-region CloudTrail trail found")
                trail_names = [t.get("Name", "unnamed") for t in trails]
                findings.append(f"Existing trails (single-region only): {', '.join(trail_names)}")
                return False, findings

            for trail in multi_region_trails:
                findings.append(f"Multi-region trail active: {trail.get('Name')}")

            return True, findings

        @self.register("cloudtrail_logging_active")
        def check_trail_status(data):
            """Verify CloudTrail is actively logging."""
            findings = []
            is_logging = data.get("IsLogging", False) if isinstance(data, dict) else False

            if not is_logging:
                findings.append("CloudTrail logging is not active")
                return False, findings

            findings.append("CloudTrail is actively logging")
            latest = data.get("LatestDeliveryTime", "unknown")
            findings.append(f"Latest log delivery: {latest}")
            return True, findings

        @self.register("guardduty_enabled")
        def check_guardduty(data):
            """Verify GuardDuty is enabled."""
            findings = []
            detectors = _extract_key(data, "DetectorIds", [])

            if not detectors:
                findings.append("GuardDuty is not enabled (no detectors found)")
                return False, findings

            findings.append(f"GuardDuty enabled with {len(detectors)} detector(s)")
            return True, findings

        @self.register("security_hub_enabled")
        def check_security_hub(data):
            """Verify Security Hub is enabled."""
            findings = []

            hub_arn = data.get("HubArn", "") if isinstance(data, dict) else ""
            if not hub_arn:
                findings.append("AWS Security Hub is not enabled")
                return False, findings

            findings.append(f"Security Hub active: {hub_arn}")
            return True, findings

        # === Network Security Assertions ===

        @self.register("no_unrestricted_ingress")
        def check_security_groups(data):
            """Flag security groups with 0.0.0.0/0 ingress on sensitive ports."""
            findings = []
            violations = []
            sensitive_ports = {22, 3389, 3306, 5432, 1433, 27017, 6379}

            security_groups = _extract_key(data, "SecurityGroups", [])

            for sg in security_groups:
                sg_id = sg.get("GroupId", "unknown")
                sg_name = sg.get("GroupName", "unknown")

                for rule in sg.get("IpPermissions", []):
                    from_port = rule.get("FromPort", 0)
                    to_port = rule.get("ToPort", 65535)

                    # Check if any sensitive port falls in the rule's range
                    rule_ports = set(range(from_port, to_port + 1))
                    exposed_ports = rule_ports & sensitive_ports

                    if not exposed_ports:
                        continue

                    for ip_range in rule.get("IpRanges", []):
                        if ip_range.get("CidrIp") == "0.0.0.0/0":
                            violations.append(
                                f"{sg_name} ({sg_id}): ports {exposed_ports} open to 0.0.0.0/0"
                            )

                    for ip_range in rule.get("Ipv6Ranges", []):
                        if ip_range.get("CidrIpv6") == "::/0":
                            violations.append(
                                f"{sg_name} ({sg_id}): ports {exposed_ports} open to ::/0"
                            )

            if violations:
                findings.extend(violations)
                findings.append(f"Total violations: {len(violations)}")
                return False, findings

            findings.append(
                f"Checked {len(security_groups)} security groups, "
                "no unrestricted ingress on sensitive ports"
            )
            return True, findings

        @self.register("default_deny_ingress")
        def check_nacls(data):
            """Verify network ACLs implement default deny."""
            findings = []
            nacls = _extract_key(data, "NetworkAcls", [])
            violations = []

            for nacl in nacls:
                nacl_id = nacl.get("NetworkAclId", "unknown")
                for entry in nacl.get("Entries", []):
                    # Check if the default rule (rule number 32767) denies all
                    if (entry.get("RuleNumber") == 32767
                            and not entry.get("Egress", True)
                            and entry.get("RuleAction") != "deny"):
                        violations.append(f"{nacl_id}: default ingress rule is not deny")

            if violations:
                findings.extend(violations)
                return False, findings

            findings.append(f"All {len(nacls)} NACLs have default deny ingress")
            return True, findings


def _extract_key(data: Any, key: str, default: Any = None) -> Any:
    """
    Safely extract a key from potentially nested or paginated response data.
    Handles both single responses and lists of paginated pages.
    """
    if isinstance(data, dict):
        return data.get(key, default)
    if isinstance(data, list):
        # Paginated responses: merge the key from all pages
        merged = []
        for page in data:
            if isinstance(page, dict) and key in page:
                val = page[key]
                if isinstance(val, list):
                    merged.extend(val)
                else:
                    return val  # Non-list value, return first occurrence
        return merged if merged else default
    return default


class ControlAssessor:
    """
    Orchestrates the assessment of evidence artifacts against control assertions.

    Takes a batch of evidence artifacts and the checks that produced them,
    runs the appropriate assertion for each, and compiles the results
    into a structured assessment report.
    """

    def __init__(self):
        self.engine = AssertionEngine()

    def assess(self, artifacts: list, checks: list[dict]) -> list[AssessmentResult]:
        """
        Assess all artifacts against their corresponding check assertions.

        Pairs each artifact with the check definition that produced it,
        then evaluates the appropriate assertion.
        """
        results = []

        # Build a lookup from (check_id, provider, region) to artifact
        artifact_map = {}
        for artifact in artifacts:
            key = (artifact.check_id, artifact.provider, artifact.region)
            artifact_map[key] = artifact

        for check in checks:
            # Find the matching artifact for this check
            matching_artifacts = [
                a for a in artifacts
                if a.check_id == check["check_id"] and a.provider == check["provider"]
            ]

            if not matching_artifacts:
                results.append(AssessmentResult(
                    control_id=check["control_id"],
                    check_id=check["check_id"],
                    assertion=check["assertion"],
                    status="not_assessed",
                    provider=check["provider"],
                    region="N/A",
                    findings=["No evidence collected for this check"],
                ))
                continue

            for artifact in matching_artifacts:
                result = self.engine.evaluate(
                    assertion_name=check["assertion"],
                    data=artifact.data,
                    control_id=check["control_id"],
                    check_id=check["check_id"],
                    provider=check["provider"],
                    region=artifact.region,
                )
                result.evidence_summary = (
                    f"Source: {artifact.provider}:{artifact.service}:{artifact.method} "
                    f"in {artifact.region}, collected {artifact.collected_at}"
                )
                results.append(result)

        return results

    def summarize(self, results: list[AssessmentResult]) -> dict:
        """Produce a summary of assessment results by status and control family."""
        summary = {
            "total_checks": len(results),
            "passed": sum(1 for r in results if r.status == "pass"),
            "failed": sum(1 for r in results if r.status == "fail"),
            "errors": sum(1 for r in results if r.status == "error"),
            "not_assessed": sum(1 for r in results if r.status == "not_assessed"),
            "by_control": {},
        }

        for result in results:
            family = result.control_id.split("-")[0]
            if family not in summary["by_control"]:
                summary["by_control"][family] = {"pass": 0, "fail": 0, "error": 0}
            if result.status in summary["by_control"][family]:
                summary["by_control"][family][result.status] += 1

        total = summary["total_checks"]
        if total > 0:
            summary["pass_rate"] = f"{(summary['passed'] / total) * 100:.1f}%"

        return summary
