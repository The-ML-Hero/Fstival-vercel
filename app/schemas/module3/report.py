from datetime import datetime
from typing import Any, Dict, List
from pydantic import BaseModel, Field
from app.schemas.module3.finding import VulnerabilityFindingResponse
from app.schemas.module3.graph import AttackChainResponse
from app.schemas.module3.risk import SecurityScoreResponse
from app.schemas.module3.security_gate import SecurityGateResponse


class ExecutiveReportResponse(BaseModel):
    project_id: str
    run_id: str
    generated_at: datetime
    executive_summary: str
    security_score: SecurityScoreResponse
    ci_gate: SecurityGateResponse
    critical_findings: List[VulnerabilityFindingResponse]
    high_findings: List[VulnerabilityFindingResponse]
    medium_findings: List[VulnerabilityFindingResponse]
    low_findings: List[VulnerabilityFindingResponse]
    attack_chains: List[AttackChainResponse]
    remediation_roadmap: List[Dict[str, Any]]
    test_statistics: Dict[str, Any]
