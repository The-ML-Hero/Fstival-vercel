from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field
from app.schemas.module3.impact import BlastRadiusResponse, BusinessImpactResponse
from app.schemas.module3.risk import RiskAssessmentResponse


class RemediationRecommendation(BaseModel):
    what_to_change: str
    why: str
    secure_design_principle: str
    example_pseudocode: str
    target_framework: str = "FastAPI / Python"


class VulnerabilityFindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    finding_id: str
    attack_id: str
    title: str
    type: str
    endpoint: str
    method: str
    severity: str
    confidence: float
    status: str  # confirmed, likely, inconclusive, false-positive
    verification_status: str  # unverified, fixed, not_fixed, regression, inconclusive
    risk_score: int
    data_sensitivity: str
    confirmed_impact: Optional[str] = None
    potential_impact: Optional[str] = None
    blast_radius_reach: str
    blast_radius_confidence: float
    blast_radius_reasoning: Optional[str] = None
    technical_explanation: Optional[str] = None
    simple_explanation: Optional[str] = None
    evidence_explanation: Optional[str] = None
    why_it_matters: Optional[str] = None
    remediation: Optional[RemediationRecommendation] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    created_at: datetime


class FindingListResponse(BaseModel):
    run_id: str
    total: int
    confirmed_count: int
    likely_count: int
    inconclusive_count: int
    findings: List[VulnerabilityFindingResponse]
