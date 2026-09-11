from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ParameterMapping(BaseModel):
    source_step: str
    source_field: str  # e.g., "id", "token", "order_id"
    target_step: str
    target_parameter: str  # e.g., "patient_id", "order_id"
    location: str = "path"  # path, query, header, body


class WorkflowStep(BaseModel):
    step_number: int
    step_name: str
    endpoint: str
    method: str
    description: Optional[str] = None
    expected_status: int = 200
    produces_parameters: List[str] = Field(default_factory=list)
    consumes_parameters: List[str] = Field(default_factory=list)


class WorkflowResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    project_id: Optional[str] = None
    workflow_name: str
    description: Optional[str] = None
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    steps: List[WorkflowStep] = Field(default_factory=list)
    parameter_mappings: List[ParameterMapping] = Field(default_factory=list)


class WorkflowAnalysisResult(BaseModel):
    workflows: List[WorkflowResponse]
    total_workflows: int
