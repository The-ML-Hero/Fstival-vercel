from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models import AttackHypothesis, Project
from app.schemas.attack_plan import AttackHypothesisResponse, AttackPlanResponse, AttackPlanSummary

router = APIRouter(prefix="/projects", tags=["Attack Plan"])


@router.get("/{project_id}/attack-plan", response_model=AttackPlanResponse)
async def get_attack_plan(
    project_id: str,
    category: Optional[str] = Query(None, description="Filter by attack category (e.g. BOLA, Authentication)"),
    min_priority: Optional[str] = Query(None, description="Filter by priority level (critical, high, medium, low)"),
    db: AsyncSession = Depends(get_db)
):
    """Retrieves all generated and prioritized attack hypotheses for a project."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = (
        select(AttackHypothesis)
        .where(AttackHypothesis.project_id == project_id)
        .options(selectinload(AttackHypothesis.mutations))
        .order_by(AttackHypothesis.priority_score.desc())
    )

    if category:
        stmt = stmt.where(AttackHypothesis.category.ilike(f"%{category}%"))
    if min_priority:
        stmt = stmt.where(AttackHypothesis.priority_level == min_priority.lower())

    res = await db.execute(stmt)
    attacks = res.scalars().all()

    # Calculate summary metrics
    all_attacks_stmt = select(AttackHypothesis).where(AttackHypothesis.project_id == project_id)
    all_res = await db.execute(all_attacks_stmt)
    all_attacks = all_res.scalars().all()

    categories_map: dict[str, int] = {}
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for a in all_attacks:
        categories_map[a.category] = categories_map.get(a.category, 0) + 1
        plevel = a.priority_level.lower()
        if plevel == "critical":
            critical_count += 1
        elif plevel == "high":
            high_count += 1
        elif plevel == "medium":
            medium_count += 1
        else:
            low_count += 1

    summary = AttackPlanSummary(
        total_attacks=len(all_attacks),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        categories_breakdown=categories_map,
    )

    return AttackPlanResponse(
        project_id=project_id,
        summary=summary,
        attack_plan=attacks,
    )


@router.get("/{project_id}/attack-plan/{attack_id}", response_model=AttackHypothesisResponse)
async def get_attack_hypothesis_by_id(
    project_id: str,
    attack_id: str,
    db: AsyncSession = Depends(get_db)
):
    """Retrieves a single attack hypothesis by its ATK-XXX code or UUID."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = (
        select(AttackHypothesis)
        .where(
            AttackHypothesis.project_id == project_id,
            (AttackHypothesis.attack_id == attack_id) | (AttackHypothesis.id == attack_id)
        )
        .options(selectinload(AttackHypothesis.mutations))
    )
    res = await db.execute(stmt)
    attack = res.scalar_one_or_none()

    if not attack:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Attack '{attack_id}' not found")

    return attack
