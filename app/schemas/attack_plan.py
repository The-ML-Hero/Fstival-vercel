from typing import List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AttackMutationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    parameter_name: str
    parameter_location: str  # "path", "query", "header", "body"
    mutation_type: str
    payload_sample: str
    rationale: str


class AttackHypothesisResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    project_id: Optional[str] = None
    attack_id: str
    category: str
    endpoint: str
    method: str
    objective: str
    preconditions: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    expected_secure_behavior: str
    reason: str
    severity: str
    exploitability: float
    impact: float
    confidence: float
    priority_score: float
    priority_level: str
    mutations: List[AttackMutationResponse] = Field(default_factory=list)


class AttackPlanSummary(BaseModel):
    total_attacks: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    categories_breakdown: dict[str, int] = Field(default_factory=dict)


class AttackPlanResponse(BaseModel):
    project_id: str
    summary: AttackPlanSummary
    attack_plan: List[AttackHypothesisResponse]
