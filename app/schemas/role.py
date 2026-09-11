from typing import Any, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class InferredRoleResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    project_id: Optional[str] = None
    role_name: str
    confidence: float = Field(ge=0.0, le=1.0)
    reasoning: str
    evidence: List[Any] = Field(default_factory=list)
    associated_endpoints: List[str] = Field(default_factory=list)


class RoleAnalysisResult(BaseModel):
    detected_roles: List[InferredRoleResponse]
    hierarchical_levels: Optional[List[str]] = None
