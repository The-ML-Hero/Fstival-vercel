from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SecurityObservation(BaseModel):
    """
    Normalized internal security observation produced by Module2ResultAdapter
    from raw Module 2 attack execution outputs.
    """
    attack_id: str
    category: str
    endpoint: str
    method: str
    status: str  # completed, failed, error
    expected_status: Optional[int] = None
    actual_status: Optional[int] = None
    status_code_matched: bool = False
    duration_ms: float = 0.0
    request_headers: Dict[str, str] = Field(default_factory=dict)
    response_headers: Dict[str, str] = Field(default_factory=dict)
    response_body: Optional[str] = None
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    objective: Optional[str] = None
    reason: Optional[str] = None
    is_adaptive: bool = False
    parent_attack_id: Optional[str] = None
