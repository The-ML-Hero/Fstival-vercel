from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class Module3Evidence(BaseModel):
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None  # Redacted
    response_time_ms: float = 0.0
    status_code_matched: bool = False


class Module3AttackResultItem(BaseModel):
    attack_id: str
    status: str  # completed, failed, error
    endpoint: str
    method: str
    category: str
    severity: str
    priority: str
    expected: Dict[str, Any] = Field(default_factory=dict)
    actual: Dict[str, Any] = Field(default_factory=dict)
    evidence: Module3Evidence
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    parent_attack_id: Optional[str] = None
    is_adaptive: bool = False
    reproducible: bool = True
    objective: Optional[str] = None
    reason: Optional[str] = None


class Module3ResultExport(BaseModel):
    """
    STABLE MODULE 3 INTEGRATION CONTRACT
    Module 3 (Vulnerability Analysis, Attack Graph, Fix Generation & Verification)
    consumes this execution result payload.
    """
    model_config = ConfigDict(extra="forbid")

    contract_version: str = Field(default="1.0.0", description="API Guardian Module 3 Result Schema Version")
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    run_id: str
    project_id: str
    target: Dict[str, Any] = Field(default_factory=dict)
    summary: Dict[str, Any] = Field(default_factory=dict)
    attack_results: List[Module3AttackResultItem]
