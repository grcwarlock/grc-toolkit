"""
vendor_monitor.py
Third-party vendor risk tracking and SLA compliance monitoring.

Automates the tedious parts of vendor risk management: pulling
security ratings, tracking questionnaire responses, monitoring
SLA metrics, and flagging vendors that need attention.
"""

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class Vendor:
    """A third-party vendor with risk metadata."""
    vendor_id: str
    name: str
    category: str                   # e.g., "cloud_infrastructure", "saas", "consulting"
    criticality: str                # critical, high, medium, low
    data_classification: str        # public, internal, confidential, restricted
    contract_start: str
    contract_end: str

    # Assessment tracking
    last_assessment_date: str = ""
    assessment_frequency_days: int = 365
    questionnaire_status: str = "pending"  # pending, sent, received, reviewed

    # SLA tracking
    sla_uptime_target: float = 99.9
    sla_response_time_hours: int = 4
    sla_resolution_time_hours: int = 24

    # Security posture
    security_rating: float | None = None
    security_rating_source: str = ""
    certifications: list[str] = field(default_factory=list)
    last_incident_date: str = ""
    breach_history: list[str] = field(default_factory=list)

    # Metadata
    primary_contact: str = ""
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class VendorRiskScore:
    """Calculated risk score for a vendor based on multiple factors."""
    vendor_id: str
    vendor_name: str
    overall_score: float            # 0-100 (higher = more risk)
    criticality_score: float
    data_sensitivity_score: float
    assessment_currency_score: float
    security_posture_score: float
    sla_compliance_score: float
    factors: list[str] = field(default_factory=list)

    def risk_level(self) -> str:
        if self.overall_score >= 75:
            return "Critical"
        if self.overall_score >= 50:
            return "High"
        if self.overall_score >= 25:
            return "Medium"
        return "Low"


class VendorRiskEngine:
    """
    Calculates composite risk scores for vendors based on multiple
    weighted factors. The scoring model can be calibrated per
    organization, but the defaults reflect common GRC practice.
    """

    # Weight each factor by its relative importance
    WEIGHTS = {
        "criticality": 0.25,
        "data_sensitivity": 0.25,
        "assessment_currency": 0.20,
        "security_posture": 0.15,
        "sla_compliance": 0.15,
    }

    def score_vendor(self, vendor: Vendor,
                     sla_metrics: dict | None = None) -> VendorRiskScore:
        """Calculate a composite risk score for a single vendor."""
        factors = []

        # Criticality score
        crit_map = {"critical": 100, "high": 75, "medium": 50, "low": 25}
        crit_score = crit_map.get(vendor.criticality, 50)

        # Data sensitivity score
        data_map = {"restricted": 100, "confidential": 75, "internal": 50, "public": 25}
        data_score = data_map.get(vendor.data_classification, 50)

        # Assessment currency: how overdue is their risk assessment?
        assess_score = self._assessment_currency_score(vendor)
        if assess_score > 50:
            factors.append(f"Risk assessment is overdue (last: {vendor.last_assessment_date})")

        # Security posture based on rating and certifications
        sec_score = self._security_posture_score(vendor)
        if sec_score > 60:
            factors.append("Weak security posture indicators")

        # SLA compliance (if metrics provided)
        sla_score = self._sla_compliance_score(vendor, sla_metrics)
        if sla_score > 50:
            factors.append("SLA compliance below target")

        overall = (
            crit_score * self.WEIGHTS["criticality"]
            + data_score * self.WEIGHTS["data_sensitivity"]
            + assess_score * self.WEIGHTS["assessment_currency"]
            + sec_score * self.WEIGHTS["security_posture"]
            + sla_score * self.WEIGHTS["sla_compliance"]
        )

        return VendorRiskScore(
            vendor_id=vendor.vendor_id,
            vendor_name=vendor.name,
            overall_score=round(overall, 1),
            criticality_score=crit_score,
            data_sensitivity_score=data_score,
            assessment_currency_score=assess_score,
            security_posture_score=sec_score,
            sla_compliance_score=sla_score,
            factors=factors,
        )

    def _assessment_currency_score(self, vendor: Vendor) -> float:
        """Score based on how recently the vendor was assessed."""
        if not vendor.last_assessment_date:
            return 100.0  # Never assessed = maximum risk

        try:
            last = datetime.fromisoformat(vendor.last_assessment_date)
            now = datetime.now(UTC)

            # Handle naive datetime by assuming UTC
            if last.tzinfo is None:
                last = last.replace(tzinfo=UTC)

            days_since = (now - last).days
            overdue_days = days_since - vendor.assessment_frequency_days

            if overdue_days <= 0:
                # Assessment is current; score based on how close to expiry
                remaining_pct = 1 - (days_since / vendor.assessment_frequency_days)
                return (1 - remaining_pct) * 40  # 0-40 range when current

            # Overdue: scales up quickly
            overdue_pct = min(overdue_days / 180, 1.0)  # Caps at 180 days overdue
            return 40 + (overdue_pct * 60)  # 40-100 range when overdue

        except (ValueError, TypeError):
            return 75.0  # Can't parse date = high risk

    def _security_posture_score(self, vendor: Vendor) -> float:
        """Score based on security rating, certifications, and breach history."""
        score = 50.0  # Default middle ground

        # Security rating (assuming 0-100 scale, lower = worse)
        if vendor.security_rating is not None:
            # Invert: high rating = low risk score
            score = max(0, 100 - vendor.security_rating)

        # Certifications reduce risk
        valuable_certs = {"SOC 2", "ISO 27001", "FedRAMP", "HITRUST", "PCI DSS"}
        matching_certs = set(vendor.certifications) & valuable_certs
        cert_reduction = len(matching_certs) * 8  # Each cert reduces score
        score = max(0, score - cert_reduction)

        # Breach history increases risk
        if vendor.breach_history:
            score = min(100, score + len(vendor.breach_history) * 15)

        return score

    def _sla_compliance_score(self, vendor: Vendor,
                              metrics: dict | None = None) -> float:
        """Score based on actual SLA performance vs targets."""
        if not metrics:
            return 50.0  # No data = assume moderate risk

        score = 0.0

        # Uptime compliance
        actual_uptime = metrics.get("uptime_pct", 100.0)
        if actual_uptime < vendor.sla_uptime_target:
            gap = vendor.sla_uptime_target - actual_uptime
            score += min(gap * 20, 50)  # Each 0.1% gap = +2 points

        # Response time compliance
        actual_response = metrics.get("avg_response_hours", 0)
        if actual_response > vendor.sla_response_time_hours:
            ratio = actual_response / vendor.sla_response_time_hours
            score += min((ratio - 1) * 25, 50)

        return min(score, 100)


class VendorInventory:
    """
    Manages the vendor inventory and provides dashboard views.

    Stores vendor data as JSON for simplicity, but this could
    easily be swapped for a database backend.
    """

    def __init__(self, inventory_path: str):
        self.path = Path(inventory_path)
        self.vendors: dict[str, Vendor] = {}
        self._load()

    def _load(self):
        """Load vendor inventory from disk."""
        if self.path.exists():
            with open(self.path) as f:
                data = json.load(f)
                for v in data.get("vendors", []):
                    vendor = Vendor(**v)
                    self.vendors[vendor.vendor_id] = vendor

    def save(self):
        """Persist vendor inventory to disk."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with open(self.path, "w") as f:
            json.dump(
                {"vendors": [v.to_dict() for v in self.vendors.values()]},
                f, indent=2,
            )

    def add_vendor(self, vendor: Vendor):
        self.vendors[vendor.vendor_id] = vendor
        self.save()

    def get_vendor(self, vendor_id: str) -> Vendor | None:
        return self.vendors.get(vendor_id)

    def vendors_needing_assessment(self) -> list[Vendor]:
        """Find vendors whose risk assessments are overdue or approaching due date."""
        now = datetime.now(UTC)
        needs_assessment = []

        for vendor in self.vendors.values():
            if not vendor.last_assessment_date:
                needs_assessment.append(vendor)
                continue

            try:
                last = datetime.fromisoformat(vendor.last_assessment_date)
                if last.tzinfo is None:
                    last = last.replace(tzinfo=UTC)

                due_date = last + timedelta(days=vendor.assessment_frequency_days)

                # Flag if overdue or due within 30 days
                if (due_date - now).days <= 30:
                    needs_assessment.append(vendor)

            except (ValueError, TypeError):
                needs_assessment.append(vendor)

        return needs_assessment

    def expiring_contracts(self, days_ahead: int = 90) -> list[Vendor]:
        """Find vendors with contracts expiring within the specified window."""
        now = datetime.now(UTC)
        cutoff = now + timedelta(days=days_ahead)
        expiring = []

        for vendor in self.vendors.values():
            try:
                end = datetime.fromisoformat(vendor.contract_end)
                if end.tzinfo is None:
                    end = end.replace(tzinfo=UTC)
                if now <= end <= cutoff:
                    expiring.append(vendor)
            except (ValueError, TypeError):
                continue

        return expiring

    def risk_dashboard(self, engine: VendorRiskEngine) -> dict:
        """
        Generate a risk dashboard view of all vendors.
        Returns sorted risk scores and summary statistics.
        """
        scores = []
        for vendor in self.vendors.values():
            score = engine.score_vendor(vendor)
            scores.append({
                "vendor": vendor.name,
                "vendor_id": vendor.vendor_id,
                "risk_level": score.risk_level(),
                "overall_score": score.overall_score,
                "criticality": vendor.criticality,
                "data_classification": vendor.data_classification,
                "factors": score.factors,
            })

        scores.sort(key=lambda x: float(x["overall_score"]), reverse=True)  # type: ignore[arg-type]

        risk_distribution = {
            "Critical": sum(1 for s in scores if s["risk_level"] == "Critical"),
            "High": sum(1 for s in scores if s["risk_level"] == "High"),
            "Medium": sum(1 for s in scores if s["risk_level"] == "Medium"),
            "Low": sum(1 for s in scores if s["risk_level"] == "Low"),
        }

        return {
            "total_vendors": len(scores),
            "risk_distribution": risk_distribution,
            "vendors_needing_assessment": len(self.vendors_needing_assessment()),
            "expiring_contracts_90d": len(self.expiring_contracts(90)),
            "vendor_scores": scores,
        }
