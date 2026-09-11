import json
from typing import Optional
from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.exceptions import SpecParsingError, ProjectNotFoundError
from app.db.session import get_db
from app.db.models import Endpoint, Parameter, AuthScheme
from app.schemas.openapi_ingest import OpenApiImportRequest, OpenApiImportResponse
from app.services.orchestrator import AnalysisPipelineOrchestrator

router = APIRouter(prefix="/projects", tags=["Ingestion"])


@router.post("/{project_id}/import/openapi", response_model=OpenApiImportResponse)
async def import_openapi_spec(
    project_id: str,
    request: Request,
    file: Optional[UploadFile] = File(None),
    db: AsyncSession = Depends(get_db)
):
    """
    Imports an OpenAPI 3.x / Swagger 2.0 specification for a project.
    Accepts raw JSON/YAML in request body or uploaded file.
    """
    spec_content = None

    # Check if uploaded file is present
    if file:
        file_bytes = await file.read()
        spec_content = file_bytes.decode("utf-8")
    else:
        # Inspect content-type / request body
        content_type = request.headers.get("content-type", "")
        if "multipart/form-data" in content_type:
            form = await request.form()
            upload_file = form.get("file")
            if upload_file and hasattr(upload_file, "read"):
                file_bytes = await upload_file.read()
                spec_content = file_bytes.decode("utf-8")
            elif "spec_content" in form:
                spec_content = str(form.get("spec_content"))
        elif "application/json" in content_type or "text/plain" in content_type or "application/x-yaml" in content_type:
            raw_body = await request.body()
            body_str = raw_body.decode("utf-8")
            try:
                parsed_json = json.loads(body_str)
                if isinstance(parsed_json, dict):
                    if "spec_content" in parsed_json and parsed_json["spec_content"]:
                        spec_content = parsed_json["spec_content"]
                    elif "spec_json" in parsed_json and parsed_json["spec_json"]:
                        spec_content = parsed_json["spec_json"]
                    else:
                        # Raw OpenAPI object supplied directly in JSON
                        spec_content = parsed_json
            except Exception:
                spec_content = body_str
        else:
            raw_body = await request.body()
            if raw_body:
                spec_content = raw_body.decode("utf-8")

    if not spec_content:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Must provide specification via request body (JSON/YAML) or file upload."
        )

    orchestrator = AnalysisPipelineOrchestrator(db)
    try:
        spec_obj = await orchestrator.ingest_openapi(project_id, spec_content)
    except ProjectNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except SpecParsingError as e:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_ENTITY, detail=f"OpenAPI Spec Error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Import failed: {str(e)}")

    # Count extracted items
    ep_count_stmt = select(func.count(Endpoint.id)).where(Endpoint.project_id == project_id)
    param_count_stmt = select(func.count(Parameter.id)).join(Endpoint).where(Endpoint.project_id == project_id)
    auth_count_stmt = select(func.count(AuthScheme.id)).where(AuthScheme.project_id == project_id)

    ep_count = (await db.execute(ep_count_stmt)).scalar() or 0
    param_count = (await db.execute(param_count_stmt)).scalar() or 0
    auth_count = (await db.execute(auth_count_stmt)).scalar() or 0

    return OpenApiImportResponse(
        project_id=project_id,
        spec_id=spec_obj.id,
        title=spec_obj.title,
        version=spec_obj.version,
        openapi_version=spec_obj.openapi_version,
        endpoints_count=ep_count,
        parameters_count=param_count,
        auth_schemes_count=auth_count,
        status="imported",
    )
