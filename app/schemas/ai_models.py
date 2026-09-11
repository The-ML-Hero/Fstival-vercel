from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class AIAttackMutation(BaseModel):
    parameter_name: str = Field(description="Name of the parameter to mutate")
    parameter_location: str = Field(description="path, query, header, or body")
    mutation_type: str = Field(description="e.g. boundary_overflow, type_juggling, negative_value, cross_tenant_id")
    payload_sample: str = Field(description="Concrete string or JSON sample payload")
    rationale: str = Field(description="Why this mutation tests this specific vulnerability")


class AIAttackHypothesis(BaseModel):
    attack_id: str = Field(description="Unique attack identifier, e.g., ATK-001")
    category: str = Field(description="Category: Authentication, Authorization, BOLA, Role Escalation, Input Validation, Parameter Tampering, Rate-Limit Testing, HTTP Method Abuse, Information Exposure, Business Logic")
    endpoint: str = Field(description="Target endpoint path, e.g., /patients/{id}")
    method: str = Field(description="HTTP method: GET, POST, PUT, PATCH, DELETE, HEAD")
    objective: str = Field(description="Clear test objective")
    preconditions: List[str] = Field(default_factory=list, description="Preconditions required before executing test")
    steps: List[str] = Field(default_factory=list, description="Ordered test execution steps")
    expected_secure_behavior: str = Field(description="What a secure API implementation must return (status code / error)")
    reason: str = Field(description="Contextual security rationale for why this attack is plausible")
    severity: str = Field(default="medium", description="critical, high, medium, low, info")
    exploitability: float = Field(default=0.7, ge=0.0, le=1.0, description="Exploitability factor from 0.0 to 1.0")
    impact: float = Field(default=0.7, ge=0.0, le=1.0, description="Potential impact factor from 0.0 to 1.0")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0, description="Hypothesis confidence from 0.0 to 1.0")
    mutations: List[AIAttackMutation] = Field(default_factory=list, description="Context-aware mutations for this attack")


class AIWorkflowStep(BaseModel):
    step_number: int
    step_name: str
    endpoint: str
    method: str
    description: Optional[str] = None
    produces_parameters: List[str] = Field(default_factory=list)
    consumes_parameters: List[str] = Field(default_factory=list)


class AIWorkflowCandidate(BaseModel):
    workflow_name: str
    description: Optional[str] = None
    confidence: float = Field(default=0.85, ge=0.0, le=1.0)
    steps: List[AIWorkflowStep] = Field(default_factory=list)


class AIInferredRole(BaseModel):
    role_name: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    reasoning: str
    evidence: List[str] = Field(default_factory=list)
    associated_endpoints: List[str] = Field(default_factory=list)


class AIResourceCandidate(BaseModel):
    name: str
    description: Optional[str] = None
    endpoints: List[str] = Field(default_factory=list)
    crud_operations: Dict[str, str] = Field(default_factory=dict)
    relationships: List[Dict[str, str]] = Field(default_factory=list)


class AIAnalysisResult(BaseModel):
    summary: str = Field(description="Executive summary of the API attack surface")
    sensitive_operations: List[str] = Field(default_factory=list, description="List of high-risk / sensitive endpoints")
    roles: List[AIInferredRole] = Field(default_factory=list)
    resources: List[AIResourceCandidate] = Field(default_factory=list)
    workflows: List[AIWorkflowCandidate] = Field(default_factory=list)
    attack_hypotheses: List[AIAttackHypothesis] = Field(default_factory=list)
