from typing import Optional
from pydantic import BaseModel, Field


class BlastRadiusResponse(BaseModel):
    estimated_reach: str = Field(..., description="Estimated reach: e.g. Single Object, All Objects in Tenant, Full Database, 10,000+ records")
    confidence: float = Field(..., ge=0.0, le=1.0)
    reasoning: str = Field(..., description="Explanation of why this reach was estimated based on parameters and access controls")
    is_estimate: bool = True


class BusinessImpactResponse(BaseModel):
    confirmed_impact: Optional[str] = Field(None, description="Impact proven by verified response evidence")
    potential_impact: Optional[str] = Field(None, description="Theoretical downstream business or operational consequence")
    impact_categories: list[str] = Field(default_factory=list, description="e.g. Data Exposure, Financial Loss, Account Takeover, Privilege Escalation")
