from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class StepExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    step_number: int
    step_name: str
    method: str
    url: str
    request_headers: Dict[str, Any] = Field(default_factory=dict)
    request_body: Optional[str] = None
    response_status: Optional[int] = None
    response_body: Optional[str] = None
    response_headers: Dict[str, Any] = Field(default_factory=dict)
    duration_ms: float = 0.0
    status: str = "passed"
    error_message: Optional[str] = None


class AttackExecutionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    run_id: str
    attack_id: str
    category: str
    endpoint: str
    method: str
    status: str  # passed, failed, error, skipped
    severity: str
    priority: str
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    duration_ms: float = 0.0
    parent_attack_id: Optional[str] = None
    is_adaptive: bool = False
    is_replay: bool = False
    objective: Optional[str] = None
    reason: Optional[str] = None
    expected_secure_behavior: Optional[str] = None
    steps: List[StepExecutionResponse] = Field(default_factory=list)


class AttackExecutionListResponse(BaseModel):
    run_id: str
    total: int
    passed: int
    failed: int
    error: int
    attacks: List[AttackExecutionResponse]


class RawExecutionResultResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    execution_id: str
    stdout: str
    stderr: str
    exit_code: int
    raw_json: Optional[Any] = None
