from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Module2ApiSummary(BaseModel):
    title: str
    version: str
    openapi_version: str
    description: Optional[str] = None
    target_base_url: Optional[str] = None
    total_endpoints: int
    total_resources: int
    total_workflows: int
    total_attacks_planned: int


class Module2Parameter(BaseModel):
    name: str
    location: str  # path, query, header, cookie
    type: str
    required: bool
    default_value: Optional[str] = None
    enum_values: Optional[List[Any]] = None
    schema_def: Optional[Dict[str, Any]] = None


class Module2Endpoint(BaseModel):
    id: str
    method: str
    path: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    security_required: bool
    tags: List[str] = Field(default_factory=list)
    security_schemes: List[Any] = Field(default_factory=list)
    parameters: List[Module2Parameter] = Field(default_factory=list)
    request_schemas: List[Dict[str, Any]] = Field(default_factory=list)
    response_schemas: List[Dict[str, Any]] = Field(default_factory=list)


class Module2Role(BaseModel):
    role_name: str
    confidence: float
    reasoning: str
    evidence: List[Any] = Field(default_factory=list)
    associated_endpoints: List[str] = Field(default_factory=list)


class Module2ResourceRelationship(BaseModel):
    target_resource: str
    relationship_type: str
    evidence_endpoint: Optional[str] = None


class Module2Resource(BaseModel):
    name: str
    description: Optional[str] = None
    endpoints: List[str] = Field(default_factory=list)
    crud_operations: Dict[str, str] = Field(default_factory=dict)
    relationships: List[Module2ResourceRelationship] = Field(default_factory=list)


class Module2WorkflowStep(BaseModel):
    step_number: int
    step_name: str
    endpoint: str
    method: str
    description: Optional[str] = None
    produces_parameters: List[str] = Field(default_factory=list)
    consumes_parameters: List[str] = Field(default_factory=list)


class Module2Workflow(BaseModel):
    workflow_name: str
    description: Optional[str] = None
    confidence: float
    steps: List[Module2WorkflowStep] = Field(default_factory=list)
    parameter_mappings: List[Dict[str, Any]] = Field(default_factory=list)


class Module2Mutation(BaseModel):
    parameter_name: str
    parameter_location: str  # path, query, header, body
    mutation_type: str
    payload_sample: str
    rationale: str


class Module2AttackItem(BaseModel):
    attack_id: str
    type: str  # BOLA, Role Escalation, Authentication, etc.
    endpoint: str
    method: str
    objective: str
    preconditions: List[str] = Field(default_factory=list)
    steps: List[str] = Field(default_factory=list)
    mutations: List[Module2Mutation] = Field(default_factory=list)
    expected_secure_behavior: str
    reason: str
    severity: str
    exploitability: float
    impact: float
    confidence: float
    priority_score: float
    priority: str  # critical, high, medium, low


class Module2AttackPlanExport(BaseModel):
    """
    STABLE MODULE 2 CONSUMPTION CONTRACT
    Module 2 (Execution / Attack Simulation) ingests this payload to generate and execute Bruno attack collections.
    """
    model_config = ConfigDict(extra="forbid")

    contract_version: str = Field(default="1.0.0", description="API Guardian Schema Contract Version")
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    project_id: str
    target_authorized: bool
    api_summary: Module2ApiSummary
    endpoints: List[Module2Endpoint]
    roles: List[Module2Role]
    resources: List[Module2Resource]
    workflows: List[Module2Workflow]
    attack_plan: List[Module2AttackItem]
