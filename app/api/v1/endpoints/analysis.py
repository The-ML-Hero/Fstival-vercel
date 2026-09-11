from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import AnalysisError, ProjectNotFoundError, TargetNotAuthorizedError
from app.db.session import get_db
from app.schemas.module2_contract import Module2AttackPlanExport
from app.services.orchestrator import AnalysisPipelineOrchestrator

router = APIRouter(prefix="/projects", tags=["Analysis"])


@router.post("/{project_id}/analyze", response_model=Module2AttackPlanExport)
async def trigger_analysis(
    project_id: str,
    ai_provider: Optional[str] = Query(None, description="Override AI provider (fallback, openai, ollama)"),
    db: AsyncSession = Depends(get_db)
):
    """
    Triggers full AI API understanding, role/resource/workflow inference,
    attack hypothesis generation across 10 security categories, mutations, and prioritization.
    """
    orchestrator = AnalysisPipelineOrchestrator(db)
    try:
        export_contract = await orchestrator.run_analysis(
            project_id=project_id,
            ai_provider_override=ai_provider
        )
        return export_contract
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetNotAuthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except AnalysisError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Analysis pipeline error: {str(e)}")
