from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import Project, SecurityScanSummary, VulnerabilityFinding, RegressionRecord
from app.schemas.module3.regression import (
    ProjectHistoryResponse,
    ProjectHistoryScanItem,
    RegressionResponse,
    ApiChangeImpactResponse,
)
from app.services.analyzers.regression_detector import RegressionDetector

router = APIRouter(prefix="/projects", tags=["Security History & Regressions"])


@router.get("/{project_id}/history", response_model=ProjectHistoryResponse)
async def get_project_scan_history(
    project_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Retrieves chronological security scan history and score trends for a project.
    """
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found")

    stmt = (
        select(SecurityScanSummary)
        .where(SecurityScanSummary.project_id == project_id)
        .order_by(desc(SecurityScanSummary.scanned_at))
    )
    scans = (await db.execute(stmt)).scalars().all()

    history_items = [
        ProjectHistoryScanItem(
            run_id=s.run_id,
            security_score=s.security_score,
            total_findings=s.total_findings,
            critical_count=s.critical_count,
            high_count=s.high_count,
            medium_count=s.medium_count,
            low_count=s.low_count,
            fixed_count=s.fixed_count,
            regression_count=s.regression_count,
            ci_gate_status=s.ci_gate_status,
            scanned_at=s.scanned_at,
        )
        for s in scans
    ]

    return ProjectHistoryResponse(
        project_id=project_id,
        total_scans=len(history_items),
        history=history_items,
    )


@router.get("/{project_id}/regressions", response_model=RegressionResponse)
async def get_project_regressions(
    project_id: str,
    current_run_id: Optional[str] = Query(None, description="Current run ID to compare"),
    previous_run_id: Optional[str] = Query(None, description="Previous baseline run ID to compare against"),
    db: AsyncSession = Depends(get_db)
):
    """
    Compares two scan runs for a project to detect regressions, newly introduced vulnerabilities,
    and fixed issues.
    """
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Project '{project_id}' not found")

    # If run IDs are not specified, select the two most recent scans
    if not current_run_id:
        stmt = (
            select(SecurityScanSummary)
            .where(SecurityScanSummary.project_id == project_id)
            .order_by(desc(SecurityScanSummary.scanned_at))
            .limit(2)
        )
        scans = (await db.execute(stmt)).scalars().all()
        if not scans:
            return RegressionResponse(
                project_id=project_id,
                current_run_id="",
                previous_run_id=None,
                new_vulnerabilities=[],
                fixed_vulnerabilities=[],
                regressions=[],
                score_delta=0,
                summary="No scans recorded for this project yet.",
            )
        current_run_id = scans[0].run_id
        if len(scans) > 1 and not previous_run_id:
            previous_run_id = scans[1].run_id

    # Fetch current findings
    curr_stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == current_run_id)
    curr_findings = (await db.execute(curr_stmt)).scalars().all()

    # Fetch previous findings
    prev_findings = []
    prev_score = None
    if previous_run_id:
        prev_stmt = select(VulnerabilityFinding).where(VulnerabilityFinding.run_id == previous_run_id)
        prev_findings = (await db.execute(prev_stmt)).scalars().all()
        prev_scan_stmt = select(SecurityScanSummary).where(SecurityScanSummary.run_id == previous_run_id)
        prev_scan = (await db.execute(prev_scan_stmt)).scalar_one_or_none()
        if prev_scan:
            prev_score = prev_scan.security_score

    detector = RegressionDetector()
    curr_scan_stmt = select(SecurityScanSummary).where(SecurityScanSummary.run_id == current_run_id)
    curr_scan = (await db.execute(curr_scan_stmt)).scalar_one_or_none()
    curr_score = curr_scan.security_score if curr_scan else 50

    return detector.compare_runs(
        project_id=project_id,
        current_run_id=current_run_id,
        current_findings=curr_findings,
        current_score=curr_score,
        previous_run_id=previous_run_id,
        previous_findings=prev_findings,
        previous_score=prev_score,
    )
