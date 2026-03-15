"""Risk simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.schemas import (
    PortfolioRequest,
    PortfolioResponse,
    SimulationResponse,
    ThreatScenarioRequest,
    TreatmentComparisonRequest,
    TreatmentComparisonResponse,
)
from api.security import require_api_key
from modules.risk_engine import EXAMPLE_SCENARIOS, RiskEngine, ThreatScenario

router = APIRouter(prefix="/api/v1/risk", tags=["risk"])


def _to_threat_scenario(req: ThreatScenarioRequest) -> ThreatScenario:
    return ThreatScenario(
        name=req.name,
        description=req.description,
        category=req.category,
        frequency_min=req.frequency_min,
        frequency_mode=req.frequency_mode,
        frequency_max=req.frequency_max,
        impact_min=req.impact_min,
        impact_mode=req.impact_mode,
        impact_max=req.impact_max,
        control_effectiveness=req.control_effectiveness,
    )


@router.post("/simulate", response_model=SimulationResponse)
async def simulate_scenario(
    request: ThreatScenarioRequest,
    iterations: int = Query(10_000, ge=100, le=100_000),
    seed: int | None = Query(None),
    api_key: str = Depends(require_api_key),
):
    engine = RiskEngine(iterations=iterations, seed=seed)
    scenario = _to_threat_scenario(request)
    result = engine.simulate_scenario(scenario)
    return SimulationResponse(
        scenario_name=result.scenario_name,
        iterations=result.iterations,
        mean_ale=round(result.mean_ale, 2),
        median_ale=round(result.median_ale, 2),
        var_90=round(result.var_90, 2),
        var_95=round(result.var_95, 2),
        var_99=round(result.var_99, 2),
        max_observed=round(result.max_observed, 2),
    )


@router.post("/portfolio", response_model=PortfolioResponse)
async def simulate_portfolio(request: PortfolioRequest, api_key: str = Depends(require_api_key)):
    engine = RiskEngine(iterations=request.iterations, seed=request.seed)
    scenarios = [_to_threat_scenario(s) for s in request.scenarios]
    result = engine.simulate_portfolio(scenarios)
    return PortfolioResponse(**result)


@router.post("/treatments", response_model=TreatmentComparisonResponse)
async def compare_treatments(request: TreatmentComparisonRequest, api_key: str = Depends(require_api_key)):
    engine = RiskEngine(iterations=request.iterations)
    scenario = _to_threat_scenario(request.scenario)
    treatments = [
        {"name": t.name, "effectiveness": t.effectiveness, "annual_cost": t.annual_cost}
        for t in request.treatments
    ]
    comparisons = engine.compare_treatments(scenario, treatments)
    return TreatmentComparisonResponse(treatments=comparisons)


@router.get("/scenarios")
async def list_scenarios(api_key: str = Depends(require_api_key)):
    """Return built-in example threat scenarios."""
    return [
        {
            "name": s.name,
            "description": s.description,
            "category": s.category,
            "frequency": {"min": s.frequency_min, "mode": s.frequency_mode, "max": s.frequency_max},
            "impact": {"min": s.impact_min, "mode": s.impact_mode, "max": s.impact_max},
            "data_source": s.data_source,
            "confidence": s.confidence,
        }
        for s in EXAMPLE_SCENARIOS
    ]


@router.get("/graph")
async def risk_graph(api_key: str = Depends(require_api_key)):
    """Generate a connected risk graph showing relationships between threats, controls, vendors, and assets."""
    nodes = []
    edges = []
    clusters = []

    # Build scenario nodes
    for i, s in enumerate(EXAMPLE_SCENARIOS):
        node_id = f"threat-{i}"
        nodes.append({
            "id": node_id,
            "type": "threat",
            "label": s.name,
            "category": s.category,
            "risk_level": "high" if s.impact_mode > 500_000 else "medium" if s.impact_mode > 100_000 else "low",
            "impact_mode": s.impact_mode,
            "frequency_mode": s.frequency_mode,
        })

    # Build control family nodes and link to threats
    control_threat_map = {
        "AC": ["Insider Threat", "Unauthorized Access"],
        "AU": ["Insider Threat", "Compliance Violation"],
        "SC": ["Ransomware Attack", "Data Breach", "DDoS Attack"],
        "IA": ["Unauthorized Access", "Data Breach"],
        "CM": ["Supply Chain Compromise", "Ransomware Attack"],
        "SI": ["Ransomware Attack", "Supply Chain Compromise"],
        "IR": ["Ransomware Attack", "Data Breach", "DDoS Attack"],
        "RA": ["Compliance Violation"],
    }
    for family, threats in control_threat_map.items():
        node_id = f"control-{family}"
        nodes.append({
            "id": node_id,
            "type": "control",
            "label": f"{family} Controls",
            "family": family,
        })
        for threat_name in threats:
            for i, s in enumerate(EXAMPLE_SCENARIOS):
                if s.name == threat_name:
                    edges.append({
                        "source": node_id,
                        "target": f"threat-{i}",
                        "relationship": "mitigates",
                        "strength": 0.7,
                    })

    # Build asset nodes
    asset_types = [
        {"id": "asset-cloud", "label": "Cloud Infrastructure", "type": "asset", "asset_type": "infrastructure"},
        {"id": "asset-data", "label": "Customer Data", "type": "asset", "asset_type": "data"},
        {"id": "asset-app", "label": "Applications", "type": "asset", "asset_type": "application"},
        {"id": "asset-endpoint", "label": "Endpoints", "type": "asset", "asset_type": "endpoint"},
    ]
    nodes.extend(asset_types)

    # Link threats to assets
    threat_asset_map = {
        "Ransomware Attack": ["asset-endpoint", "asset-data", "asset-app"],
        "Data Breach": ["asset-data", "asset-cloud"],
        "DDoS Attack": ["asset-app", "asset-cloud"],
        "Insider Threat": ["asset-data", "asset-app"],
        "Supply Chain Compromise": ["asset-app", "asset-cloud"],
    }
    for threat_name, assets in threat_asset_map.items():
        for i, s in enumerate(EXAMPLE_SCENARIOS):
            if s.name == threat_name:
                for asset_id in assets:
                    edges.append({
                        "source": f"threat-{i}",
                        "target": asset_id,
                        "relationship": "targets",
                        "strength": 0.8,
                    })

    # Build vendor nodes
    vendor_nodes = [
        {"id": "vendor-cloud", "label": "Cloud Provider (AWS)", "type": "vendor", "criticality": "Critical"},
        {"id": "vendor-idp", "label": "Identity Provider (Okta)", "type": "vendor", "criticality": "Critical"},
        {"id": "vendor-siem", "label": "SIEM (Splunk)", "type": "vendor", "criticality": "High"},
    ]
    nodes.extend(vendor_nodes)

    # Link vendors to assets
    edges.extend([
        {"source": "vendor-cloud", "target": "asset-cloud", "relationship": "provides", "strength": 0.9},
        {"source": "vendor-idp", "target": "control-IA", "relationship": "supports", "strength": 0.9},
        {"source": "vendor-siem", "target": "control-AU", "relationship": "supports", "strength": 0.8},
    ])

    # Clusters
    clusters = [
        {"id": "cluster-threats", "label": "Threat Landscape", "node_ids": [n["id"] for n in nodes if n["type"] == "threat"]},
        {"id": "cluster-controls", "label": "Control Framework", "node_ids": [n["id"] for n in nodes if n["type"] == "control"]},
        {"id": "cluster-assets", "label": "Assets", "node_ids": [n["id"] for n in nodes if n["type"] == "asset"]},
        {"id": "cluster-vendors", "label": "Third Parties", "node_ids": [n["id"] for n in nodes if n["type"] == "vendor"]},
    ]

    return {
        "nodes": nodes,
        "edges": edges,
        "clusters": clusters,
        "summary": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "threat_count": sum(1 for n in nodes if n["type"] == "threat"),
            "control_count": sum(1 for n in nodes if n["type"] == "control"),
            "asset_count": sum(1 for n in nodes if n["type"] == "asset"),
            "vendor_count": sum(1 for n in nodes if n["type"] == "vendor"),
        },
    }
