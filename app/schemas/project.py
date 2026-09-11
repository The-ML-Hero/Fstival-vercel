from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class ProjectCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255, description="Project or API name")
    description: Optional[str] = Field(default=None, description="Optional project description")
    target_base_url: Optional[str] = Field(default=None, max_length=512, description="Target API base URL (for future execution)")
    target_authorized: bool = Field(default=False, description="Whether testing on this target is explicitly authorized")


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=255)
    description: Optional[str] = None
    target_base_url: Optional[str] = None
    target_authorized: Optional[bool] = None


class ProjectResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    description: Optional[str]
    target_base_url: Optional[str]
    target_authorized: bool
    created_at: datetime
    updated_at: datetime
