from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TargetConfig(BaseModel):
    base_url: str = Field(..., description="Target API base URL (e.g. http://localhost:8080/api/v1)")
    authorized: bool = Field(default=False, description="Explicit authorization flag")
    environment: str = Field(default="local", description="Environment: local, staging, or authorized")
    auth_tokens: Dict[str, str] = Field(default_factory=dict, description="Pre-configured role tokens (user, admin, etc.)")


class AttackScenarioStep(BaseModel):
    step_number: int
    step_name: str
    method: str
    path: str
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, Any] = Field(default_factory=dict)
    body: Optional[Any] = None
    expected_status: int = 403
    produces_vars: Dict[str, str] = Field(default_factory=dict, description="Map extracted response fields to context vars")
    consumes_vars: Dict[str, str] = Field(default_factory=dict, description="Map context vars to request parameters")


class AttackScenario(BaseModel):
    scenario_id: str
    attack_id: str
    category: str
    endpoint: str
    method: str
    objective: str
    preconditions: List[str] = Field(default_factory=list)
    steps: List[AttackScenarioStep] = Field(default_factory=list)
    mutations: List[Dict[str, Any]] = Field(default_factory=list)
    expected_secure_behavior: str
    expected_status: int = 403
    severity: str = "medium"
    priority: str = "medium"
    role_required: str = "user"
    is_adaptive: bool = False
    parent_attack_id: Optional[str] = None
    reason: Optional[str] = None


class ExecutionResultSummary:
    def __init__(
        self,
        scenario: AttackScenario,
        status: str,  # "passed", "failed", "error"
        actual_status: Optional[int],
        expected_status: Optional[int],
        duration_ms: float,
        step_results: List[Dict[str, Any]],
        stdout: str = "",
        stderr: str = "",
        exit_code: int = 0
    ):
        self.scenario = scenario
        self.status = status
        self.actual_status = actual_status
        self.expected_status = expected_status
        self.duration_ms = duration_ms
        self.step_results = step_results
        self.stdout = stdout
        self.stderr = stderr
        self.exit_code = exit_code
