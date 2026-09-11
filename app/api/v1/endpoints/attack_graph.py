from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import AttackGraphModel, AttackChainModel, VulnerabilityFinding, TestRun
from app.schemas.module3.graph import (
    AttackGraphResponse,
    AttackChainListResponse,
    AttackChainResponse,
)
from app.services.analysis_orchestrator import Module3AnalysisOrchestrator

router = APIRouter(prefix="/runs", tags=["Attack Graphs & Chains"])


@router.get("/{run_id}/attack-graph", response_model=AttackGraphResponse)
async def get_attack_graph(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves full interactive attack graph connecting roles, endpoints, vulnerabilities, and impacts.
    """
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Test run '{run_id}' not found")

    stmt = select(AttackGraphModel).where(AttackGraphModel.run_id == run_id)
    graph_model = (await db.execute(stmt)).scalar_one_or_none()

    if not graph_model:
        orchestrator = Module3AnalysisOrchestrator(db)
        await orchestrator.analyze_run(run_id)
        graph_model = (await db.execute(stmt)).scalar_one_or_none()

    if not graph_model:
        return AttackGraphResponse(run_id=run_id, nodes=[], edges=[])

    return AttackGraphResponse(
        run_id=run_id,
        nodes=graph_model.nodes_json,
        edges=graph_model.edges_json,
    )


@router.get("/{run_id}/attack-chains", response_model=AttackChainListResponse)
async def list_attack_chains(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves multi-stage compound attack paths discovered by chaining multiple vulnerability findings.
    """
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Test run '{run_id}' not found")

    stmt = select(AttackChainModel).where(AttackChainModel.run_id == run_id)
    chain_models = (await db.execute(stmt)).scalars().all()

    if not chain_models:
        orchestrator = Module3AnalysisOrchestrator(db)
        await orchestrator.analyze_run(run_id)
        chain_models = (await db.execute(stmt)).scalars().all()

    chains = [
        AttackChainResponse(
            chain_id=cm.chain_id,
            title=cm.title,
            overall_risk=cm.overall_risk,
            explanation=cm.explanation,
            nodes=cm.nodes_json,
            edges=cm.edges_json,
        )
        for cm in chain_models
    ]

    return AttackChainListResponse(
        run_id=run_id,
        total_chains=len(chains),
        chains=chains,
    )
