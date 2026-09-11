from fastapi import APIRouter

# Module 1 Endpoints
from app.api.v1.endpoints.projects import router as projects_router
from app.api.v1.endpoints.ingestion import router as ingestion_router
from app.api.v1.endpoints.discovery import router as discovery_router
from app.api.v1.endpoints.analysis import router as analysis_router
from app.api.v1.endpoints.attack_plan import router as attack_plan_router
from app.api.v1.endpoints.export import router as export_router

# Module 2 Endpoints
from app.api.v1.endpoints.runs import router as runs_router
from app.api.v1.endpoints.attack_executions import router as attack_executions_router
from app.api.v1.endpoints.replay import router as replay_router
from app.api.v1.endpoints.export_module3 import router as export_module3_router

# Module 3 Endpoints
from app.api.v1.endpoints.findings import router as findings_router
from app.api.v1.endpoints.score import router as score_router
from app.api.v1.endpoints.attack_graph import router as attack_graph_router
from app.api.v1.endpoints.report import router as report_router
from app.api.v1.endpoints.fix_verification import router as fix_verification_router
from app.api.v1.endpoints.history import router as history_router
from app.api.v1.endpoints.security_gate import router as security_gate_router

api_v1_router = APIRouter()

# Module 1 Routes
api_v1_router.include_router(projects_router)
api_v1_router.include_router(ingestion_router)
api_v1_router.include_router(discovery_router)
api_v1_router.include_router(analysis_router)
api_v1_router.include_router(attack_plan_router)
api_v1_router.include_router(export_router)

# Module 2 Routes
api_v1_router.include_router(runs_router)
api_v1_router.include_router(attack_executions_router)
api_v1_router.include_router(replay_router)
api_v1_router.include_router(export_module3_router)

# Module 3 Routes
api_v1_router.include_router(findings_router)
api_v1_router.include_router(score_router)
api_v1_router.include_router(attack_graph_router)
api_v1_router.include_router(report_router)
api_v1_router.include_router(fix_verification_router)
api_v1_router.include_router(history_router)
api_v1_router.include_router(security_gate_router)
