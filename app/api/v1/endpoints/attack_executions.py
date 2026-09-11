from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models import AttackExecution, TestRun
from app.schemas.attack_result import AttackExecutionListResponse, AttackExecutionResponse

router = APIRouter(prefix="/runs", tags=["Attack Executions"])


@router.get("/{run_id}/attacks", response_model=AttackExecutionListResponse)
async def list_run_attacks(
    run_id: str,
    status_filter: Optional[str] = Query(None, description="Filter by status: passed, failed, error"),
    category: Optional[str] = Query(None, description="Filter by category"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves all attack executions and step results for a specific test run."""
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Test run not found")

    stmt = (
        select(AttackExecution)
        .where(AttackExecution.run_id == run_id)
        .options(selectinload(AttackExecution.steps))
        .order_by(AttackExecution.created_at)
    )
    if status_filter:
        stmt = stmt.where(AttackExecution.status == status_filter.lower())
    if category:
        stmt = stmt.where(AttackExecution.category.ilike(f"%{category}%"))

    res = await db.execute(stmt)
    attacks = res.scalars().all()

    passed_c = sum(1 for a in attacks if a.status == "passed")
    failed_c = sum(1 for a in attacks if a.status == "failed")
    error_c = sum(1 for a in attacks if a.status == "error")

    return AttackExecutionListResponse(
        run_id=run_id,
        total=len(attacks),
        passed=passed_c,
        failed=failed_c,
        error=error_c,
        attacks=attacks,
    )


@router.get("/{run_id}/attacks/{attack_id}", response_model=AttackExecutionResponse)
async def get_attack_execution_detail(
    run_id: str,
    attack_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Retrieves step-by-step evidence and assertion results for a specific attack execution."""
    stmt = (
        select(AttackExecution)
        .where(
            AttackExecution.run_id == run_id,
            (AttackExecution.attack_id == attack_id) | (AttackExecution.id == attack_id)
        )
        .options(selectinload(AttackExecution.steps))
    )
    res = await db.execute(stmt)
    attack = res.scalar_one_or_none()

    if not attack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack '{attack_id}' not found in run '{run_id}'")

    return attack
