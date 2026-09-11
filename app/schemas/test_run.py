from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field


class TestRunCreate(BaseModel):
    __test__ = False

    target_base_url: Optional[str] = Field(default=None, description="Override target base URL")
    target_authorized: bool = Field(default=True, description="Must be true to execute tests")
    environment: str = Field(default="local", description="Environment tier: local, staging, or authorized")
    auth_tokens: Optional[Dict[str, str]] = Field(default=None, description="Optional map of role -> token")
    max_adaptive_depth: Optional[int] = Field(default=None, description="Override max adaptive depth limit")


class TestRunResponse(BaseModel):
    __test__ = False
    model_config = ConfigDict(from_attributes=True)

    id: str
    project_id: str
    target_base_url: str
    target_authorized: bool
    environment: str
    status: str
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    total_attacks: int = 0
    passed_attacks: int = 0
    failed_attacks: int = 0
    error_attacks: int = 0
    collection_path: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime
