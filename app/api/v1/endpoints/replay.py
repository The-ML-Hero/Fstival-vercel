from typing import Any, Dict
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import ProjectNotFoundError, TargetNotAuthorizedError
from app.db.session import get_db
from app.services.execution_orchestrator import Module2ExecutionOrchestrator

router = APIRouter(prefix="/runs", tags=["Attack Replay"])


@router.post("/{run_id}/attacks/{attack_id}/replay")
async def replay_attack_execution(
    run_id: str,
    attack_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Replays a specific attack execution with identical parameters to verify reproducibility.
    """
    orchestrator = Module2ExecutionOrchestrator(db)
    try:
        replay_record = await orchestrator.replay_attack(run_id, attack_id)
        return {
            "status": replay_record.status,
            "diff_summary": replay_record.diff_summary,
            "original_execution_id": replay_record.original_execution_id,
            "replayed_execution_id": replay_record.replayed_execution_id,
            "replayed_at": replay_record.replayed_at.isoformat(),
        }
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetNotAuthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Replay failed: {str(e)}")
