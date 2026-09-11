from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class RegressionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    project_id: str
    current_run_id: str
    previous_run_id: Optional[str]
    new_vulnerabilities: List[Dict[str, Any]]
    fixed_vulnerabilities: List[Dict[str, Any]]
    regressions: List[Dict[str, Any]]
    score_delta: int
    summary: str


class ProjectHistoryScanItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    run_id: str
    security_score: int
    total_findings: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    fixed_count: int
    regression_count: int
    ci_gate_status: str
    scanned_at: datetime


class ProjectHistoryResponse(BaseModel):
    project_id: str
    total_scans: int
    history: List[ProjectHistoryScanItem]


class ApiChangeImpactResponse(BaseModel):
    project_id: str
    changed_endpoints: List[str]
    affected_workflows: List[str]
    affected_findings: List[str]
    recommended_retest_scenarios: List[str]
