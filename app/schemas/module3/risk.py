from typing import Dict
from pydantic import BaseModel, Field


class RiskBreakdown(BaseModel):
    severity_weight: float = Field(..., description="Normalized severity component (0-40)")
    exploitability_factor: float = Field(..., description="Exploitability multiplier (0-25)")
    confidence_factor: float = Field(..., description="Evidence confidence weight (0-15)")
    data_sensitivity_factor: float = Field(..., description="Data sensitivity impact (0-10)")
    reach_factor: float = Field(..., description="Blast radius reach score (0-10)")
    calculation_formula: str = Field(..., description="Formula used to derive final risk score")


class RiskAssessmentResponse(BaseModel):
    risk_score: int = Field(..., ge=0, le=100, description="Overall risk score between 0 and 100")
    severity: str
    confidence: float
    breakdown: RiskBreakdown
    reasoning: str


class SecurityScoreResponse(BaseModel):
    run_id: str
    security_score: int = Field(..., ge=0, le=100, description="Overall security rating: 100 is pristine, 0 is fully compromised")
    risk_level: str  # low, medium, high, critical
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    score_calculation_details: Dict[str, float]
