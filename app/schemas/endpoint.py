from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class ParameterSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    name: str
    location: str  # "path", "query", "header", "cookie"
    param_type: str = "string"
    required: bool = False
    default_value: Optional[str] = None
    enum_values: Optional[List[Any]] = None
    schema_def: Optional[Dict[str, Any]] = None
    description: Optional[str] = None


class SchemaModelSchema(BaseModel):
    model_config = ConfigDict(from_attributes=True, populate_by_name=True)

    id: Optional[str] = None
    schema_type: str  # "request_body" or "response_body"
    status_code: Optional[str] = None
    content_type: str = "application/json"
    schema_definition: Dict[str, Any] = Field(default_factory=dict, alias="schema_json")
    description: Optional[str] = None


class EndpointResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    method: str
    path: str
    operation_id: Optional[str] = None
    summary: Optional[str] = None
    description: Optional[str] = None
    security_required: bool
    tags: List[str] = Field(default_factory=list)
    security_schemes: List[Any] = Field(default_factory=list)
    responses_summary: List[str] = Field(default_factory=list)
    parameters: List[ParameterSchema] = Field(default_factory=list)
    schemas: List[SchemaModelSchema] = Field(default_factory=list)
