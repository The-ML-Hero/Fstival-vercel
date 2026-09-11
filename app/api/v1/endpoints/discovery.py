from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.db.models import Endpoint, ResourceEntity, Workflow, InferredRole, AuthScheme, Project
from app.schemas.endpoint import EndpointResponse
from app.schemas.resource import ResourceEntityResponse
from app.schemas.workflow import WorkflowResponse
from app.schemas.role import InferredRoleResponse
from app.schemas.auth import AuthSchemeResponse

router = APIRouter(prefix="/projects", tags=["Discovery"])


@router.get("/{project_id}/endpoints", response_model=List[EndpointResponse])
async def get_project_endpoints(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves all normalized discovered endpoints, parameters, and schemas."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = (
        select(Endpoint)
        .where(Endpoint.project_id == project_id)
        .options(selectinload(Endpoint.parameters), selectinload(Endpoint.schemas))
        .order_by(Endpoint.path, Endpoint.method)
    )
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{project_id}/resources", response_model=List[ResourceEntityResponse])
async def get_project_resources(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves inferred business resources and entity relationships."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = select(ResourceEntity).where(ResourceEntity.project_id == project_id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{project_id}/workflows", response_model=List[WorkflowResponse])
async def get_project_workflows(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves discovered multi-step business workflows."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = select(Workflow).where(Workflow.project_id == project_id)
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{project_id}/roles", response_model=List[InferredRoleResponse])
async def get_project_roles(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves inferred roles and permissions."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = select(InferredRole).where(InferredRole.project_id == project_id).order_by(InferredRole.confidence.desc())
    res = await db.execute(stmt)
    return res.scalars().all()


@router.get("/{project_id}/auth-schemes", response_model=List[AuthSchemeResponse])
async def get_project_auth_schemes(project_id: str, db: AsyncSession = Depends(get_db)):
    """Retrieves detected authentication schemes."""
    project = await db.get(Project, project_id)
    if not project:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Project not found")

    stmt = select(AuthScheme).where(AuthScheme.project_id == project_id)
    res = await db.execute(stmt)
    return res.scalars().all()
