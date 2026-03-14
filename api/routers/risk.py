"""Risk simulation endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from api.security import require_api_key

from api.schemas import (
    PortfolioRequest,
    PortfolioResponse,
    SimulationResponse,
    ThreatScenarioRequest,
    TreatmentComparisonRequest,
    TreatmentComparisonResponse,
)
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
