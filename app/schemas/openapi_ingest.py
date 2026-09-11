from typing import Any, Dict, Optional
from pydantic import BaseModel, Field


class OpenApiImportRequest(BaseModel):
    spec_content: Optional[str] = Field(default=None, description="Raw OpenAPI spec string (JSON or YAML)")
    spec_json: Optional[Dict[str, Any]] = Field(default=None, description="Parsed OpenAPI JSON dictionary")
    spec_url: Optional[str] = Field(default=None, description="URL pointing to OpenAPI specification")


class OpenApiImportResponse(BaseModel):
    project_id: str
    spec_id: str
    title: str
    version: str
    openapi_version: str
    endpoints_count: int
    parameters_count: int
    auth_schemes_count: int
    status: str = "imported"
