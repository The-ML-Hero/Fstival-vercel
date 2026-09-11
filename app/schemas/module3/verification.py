from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict, Field


class FixVerificationRequest(BaseModel):
    override_base_url: Optional[str] = Field(default=None, description="Optional override URL for patched staging server")


class FixVerificationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    previous_status: str
    new_status: str
    result: str  # fixed, not_fixed, regression, inconclusive
    diff_summary: str
    verified_at: datetime
