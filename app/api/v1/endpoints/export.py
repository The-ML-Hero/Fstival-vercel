from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.schemas.module2_contract import Module2AttackPlanExport
from app.services.orchestrator import AnalysisPipelineOrchestrator

router = APIRouter(prefix="/projects", tags=["Module 2 Export"])


@router.get("/{project_id}/export/module2", response_model=Module2AttackPlanExport)
async def export_for_module2(project_id: str, db: AsyncSession = Depends(get_db)):
    """
    Exports the complete API analysis, endpoints, roles, resources, workflows,
    and attack plan strictly conforming to the Module 2 consumption contract.
    """
    orchestrator = AnalysisPipelineOrchestrator(db)
    try:
        export_payload = await orchestrator.build_module2_export(project_id)
        return export_payload
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Export failed: {str(e)}")
