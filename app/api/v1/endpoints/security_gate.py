from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import VulnerabilityFinding, TestRun
from app.schemas.module3.security_gate import SecurityGatePolicy, SecurityGateResponse
from app.services.analysis_orchestrator import Module3AnalysisOrchestrator
from app.services.analyzers.ci_gate_engine import CIGateEngine
from app.services.analyzers.risk_engine import RiskEngine

router = APIRouter(prefix="/runs", tags=["CI/CD Security Gate"])


@router.post("/{run_id}/security-gate", response_model=SecurityGateResponse)
async def evaluate_security_gate(
    run_id: str,
    policy: Optional[SecurityGatePolicy] = None,
    db: AsyncSession = Depends(get_db)
):
    """
    Evaluates automated CI/CD pass/fail criteria against scan findings.
    Returns status: 'passed' (exit 0) or 'failed' (exit 1) with specific blocking findings.
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
    score_resp = risk_engine.calculate_project_security_score(
        run_id=run_id,
        findings_severities=[f.severity for f in findings if f.status in {"confirmed", "likely"}]
    )

    gate_engine = CIGateEngine()
    return gate_engine.evaluate(findings, score_resp.security_score, policy=policy)
