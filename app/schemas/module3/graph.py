from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphNode(BaseModel):
    id: str
    label: str
    type: str  # role, endpoint, vulnerability, resource, attack_step, impact
    metadata: Dict[str, Any] = Field(default_factory=dict)


class GraphEdge(BaseModel):
    source: str
    target: str
    relation: str  # accesses, exploits, exposes, escalates_to, results_in
    label: Optional[str] = None


class AttackGraphResponse(BaseModel):
    run_id: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class AttackChainResponse(BaseModel):
    chain_id: str
    title: str
    overall_risk: int
    explanation: str
    nodes: List[GraphNode]
    edges: List[GraphEdge]


class AttackChainListResponse(BaseModel):
    run_id: str
    total_chains: int
    chains: List[AttackChainResponse]
