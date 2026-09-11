from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import VulnerabilityFinding, TestRun
from app.schemas.module3.finding import FindingListResponse, VulnerabilityFindingResponse
from app.services.analysis_orchestrator import Module3AnalysisOrchestrator

router = APIRouter(prefix="/runs", tags=["Security Findings"])


@router.get("/{run_id}/findings", response_model=FindingListResponse)
async def list_findings(
    run_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity: critical, high, medium, low"),
    status_filter: Optional[str] = Query(None, description="Filter by status: confirmed, likely, inconclusive, false-positive"),
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves all vulnerability findings and risk scores for a specific test run.
    Automatically runs Module 3 analysis pipeline if findings have not yet been generated.
    """
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Test run '{run_id}' not found")

    stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == run_id)
    findings = (await db.execute(stmt)).scalars().all()

    if not findings:
        orchestrator = Module3AnalysisOrchestrator(db)
        try:
            findings = await orchestrator.analyze_run(run_id)
        except Exception as e:
            raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Analysis failed: {str(e)}")

    if severity:
        findings = [f for f in findings if f.severity.lower() == severity.lower()]
    if status_filter:
        findings = [f for f in findings if f.status.lower() == status_filter.lower()]

    orchestrator = Module3AnalysisOrchestrator(db)
    formatted = [orchestrator._format_finding_resp(f) for f in findings]

    confirmed_c = sum(1 for f in findings if f.status == "confirmed")
    likely_c = sum(1 for f in findings if f.status == "likely")
    inconclusive_c = sum(1 for f in findings if f.status == "inconclusive")

    return FindingListResponse(
        run_id=run_id,
        total=len(findings),
        confirmed_count=confirmed_c,
        likely_count=likely_c,
        inconclusive_count=inconclusive_c,
        findings=formatted,
    )


@router.get("/{run_id}/findings/{finding_id}", response_model=VulnerabilityFindingResponse)
async def get_finding_detail(
    run_id: str,
    finding_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves complete details, evidence explanation, risk breakdown, and remediation pseudocode for a finding.
    """
    stmt = select(VulnerabilityFinding).where(
        VulnerabilityFinding.run_id == run_id,
        (VulnerabilityFinding.id == finding_id) | (VulnerabilityFinding.finding_id == finding_id)
    )
    finding = (await db.execute(stmt)).scalar_one_or_none()

    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Finding '{finding_id}' not found in run '{run_id}'"
        )

    orchestrator = Module3AnalysisOrchestrator(db)
    return orchestrator._format_finding_resp(finding)
