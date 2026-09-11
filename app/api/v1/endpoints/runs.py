from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.core.exceptions import ProjectNotFoundError, TargetNotAuthorizedError
from app.db.session import get_db
from app.db.models import TestRun, RawExecutionResult, AttackExecution
from app.schemas.test_run import TestRunCreate, TestRunResponse
from app.schemas.attack_result import RawExecutionResultResponse
from app.services.execution_orchestrator import Module2ExecutionOrchestrator

router = APIRouter(tags=["Test Runs"])


@router.post("/projects/{project_id}/runs", response_model=TestRunResponse, status_code=status.HTTP_201_CREATED)
async def create_test_run(
    project_id: str,
    payload: TestRunCreate,
    db: AsyncSession = Depends(get_db)
):
    """
    Creates a new security test run for a project and generates Bruno collections on disk.
    """
    orchestrator = Module2ExecutionOrchestrator(db)
    try:
        test_run = await orchestrator.create_test_run(project_id, payload)
        return test_run
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetNotAuthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Run creation failed: {str(e)}")


@router.get("/runs/{run_id}", response_model=TestRunResponse)
async def get_test_run(run_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves status, statistics, and details of a test run."""
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Test run not found")
    return test_run


@router.post("/runs/{run_id}/start", response_model=TestRunResponse)
async def start_test_run(
    run_id: str,
    db: AsyncSession = Depends(get_db)
):
    """
    Starts execution of all attack scenarios in the test run via Bruno and async runner.
    """
    orchestrator = Module2ExecutionOrchestrator(db)
    try:
        completed_run = await orchestrator.execute_test_run(run_id)
        return completed_run
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except TargetNotAuthorizedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Execution error: {str(e)}")


@router.post("/runs/{run_id}/stop", response_model=TestRunResponse)
async def stop_test_run(run_id: str, db: AsyncSession = Depends(get_db)):
    """Stops an active test run."""
    test_run = await db.get(TestRun, run_id)
    if not test_run:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Test run not found")

    test_run.status = "stopped"
    await db.commit()
    await db.refresh(test_run)
    return test_run


@router.get("/runs/{run_id}/raw-results", response_model=List[RawExecutionResultResponse])
async def get_raw_results(run_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves raw execution outputs (stdout, stderr, exit codes) for all attacks in a run."""
    stmt = (
        select(RawExecutionResult)
        .join(AttackExecution)
        .where(AttackExecution.run_id == run_id)
    )
    res = await db.execute(stmt)
    return res.scalars().all()
