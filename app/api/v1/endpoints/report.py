from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.db.models import TestRun
from app.schemas.module3.report import ExecutiveReportResponse
from app.services.analysis_orchestrator import Module3AnalysisOrchestrator

router = APIRouter(prefix="/runs", tags=["Executive Security Report"])


@router.get("/{run_id}/report", response_model=ExecutiveReportResponse)
async def get_run_report(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Generates a structured executive security assessment report with risk score,
    findings, attack chains, remediation roadmap, and CI gate results.
    """
    orchestrator = Module3AnalysisOrchestrator(db)
    try:
        report = await orchestrator.get_executive_report(run_id)
        return report
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Report generation failed: {str(e)}")
