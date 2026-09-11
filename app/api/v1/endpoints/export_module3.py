from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError
from app.db.session import get_db
from app.schemas.module3_contract import Module3ResultExport
from app.services.execution_orchestrator import Module2ExecutionOrchestrator

router = APIRouter(prefix="/runs", tags=["Module 3 Export"])


@router.get("/{run_id}/export/module3", response_model=Module3ResultExport)
async def export_for_module3(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Exports test run results, redacted evidence, execution steps, and timings
    strictly conforming to the Module 3 consumption contract.
    """
    orchestrator = Module2ExecutionOrchestrator(db)
    try:
        export_payload = await orchestrator.build_module3_export(run_id)
        return export_payload
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Export failed: {str(e)}")
