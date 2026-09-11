from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import VulnerabilityFinding, TestRun
from app.schemas.module3.risk import SecurityScoreResponse
from app.services.analysis_orchestrator import Module3AnalysisOrchestrator
from app.services.analyzers.risk_engine import RiskEngine

router = APIRouter(prefix="/runs", tags=["Security Score"])


@router.get("/{run_id}/score", response_model=SecurityScoreResponse)
async def get_run_security_score(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves overall 0-100 security health score, risk level, and transparent deduction breakdown.
    """
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Test run '{run_id}' not found")

    stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == run_id)
    findings = (await db.execute(stmt)).scalars().all()

    if not findings:
        orchestrator = Module3AnalysisOrchestrator(db)
        findings = await orchestrator.analyze_run(run_id)

    risk_engine = RiskEngine()
    return risk_engine.calculate_project_security_score(
        run_id=run_id,
        findings_severities=[f.severity for f in findings if f.status in {"confirmed", "likely"}]
    )
