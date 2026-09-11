from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ResourceRelationship(BaseModel):
    target_resource: str
    relationship_type: str  # "has_many", "belongs_to", "operates_on", "references"
    evidence_endpoint: Optional[str] = None
    foreign_key_parameter: Optional[str] = None


class ResourceEntityResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    project_id: Optional[str] = None
    name: str
    description: Optional[str] = None
    endpoints: List[str] = Field(default_factory=list)
    crud_operations: Dict[str, str] = Field(default_factory=dict)
    relationships: List[ResourceRelationship] = Field(default_factory=list)


class ResourceAnalysisResult(BaseModel):
    resources: List[ResourceEntityResponse]
    identified_resource_count: int
