from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class AuthSchemeResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: Optional[str] = None
    project_id: Optional[str] = None
    scheme_name: str
    scheme_type: str  # bearer, apikey, basic, oauth2, none
    security_required: bool = True
    token_location: Optional[str] = None
    header_name: Optional[str] = None
    bearer_format: Optional[str] = None
    scopes: Optional[Dict[str, str]] = None
    description: Optional[str] = None


class AuthAnalysisResult(BaseModel):
    schemes: List[AuthSchemeResponse]
    global_security_required: bool
    unauthenticated_endpoints: List[str] = Field(default_factory=list)
    authenticated_endpoints: List[str] = Field(default_factory=list)
