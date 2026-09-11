from typing import List, Optional
from pydantic import BaseModel, Field


class SecurityGatePolicy(BaseModel):
    fail_on_critical: bool = Field(default=True, description="Fail CI if any confirmed critical vulnerability exists")
    max_allowed_high: int = Field(default=0, description="Maximum allowed high severity vulnerabilities")
    max_allowed_medium: int = Field(default=5, description="Maximum allowed medium severity vulnerabilities")
    min_security_score: int = Field(default=75, description="Minimum acceptable security score (0-100)")
    block_on_unverified_fixes: bool = Field(default=False, description="Block if regressions or unfixed issues are found")


class SecurityGateResponse(BaseModel):
    status: str = Field(..., description="'passed' or 'failed'")
    exit_code: int = Field(..., description="0 for passed, 1 for failed")
    reason: str
    security_score: int
    blocking_findings: List[str]
    policy_applied: SecurityGatePolicy
