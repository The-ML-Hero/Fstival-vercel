import shutil
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import text

from app.core.config import settings
from app.core.logging import logger
from app.core.exceptions import APIGuardianException
from app.db.session import init_db, engine
from app.api.v1.router import api_v1_router
from app.demo_api.server import demo_app


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle manager for startup and shutdown routines."""
    logger.info(f"Starting {settings.APP_NAME} in [{settings.APP_ENV}] mode.")
    await init_db()
    logger.info("Database initialized successfully.")
    yield
    logger.info("Shutting down API Guardian.")


def create_application() -> FastAPI:
    """Factory function for FastAPI application instance."""
    app = FastAPI(
        title=settings.APP_NAME,
        description="API Guardian: AI-Powered API Security & Attack Simulation Platform (Modules 1, 2, 3 & Frontend UI)",
        version="3.0.0",
        lifespan=lifespan,
    )

    # CORS configuration
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.ALLOWED_ORIGINS,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Global Exception Handlers
    @app.exception_handler(APIGuardianException)
    async def custom_exception_handler(request: Request, exc: APIGuardianException):
        logger.error(f"Domain exception: {exc.message}")
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"error": exc.__class__.__name__, "message": exc.message, "details": exc.details},
        )

    # Health Checks
    @app.get("/health", tags=["Health"])
    async def health_check():
        return {
            "status": "healthy",
            "service": "api-guardian",
            "version": "3.0.0",
            "modules": [
                "Module 1: API Intelligence & Attack Planning",
                "Module 2: Bruno Execution & Adaptive Simulation",
                "Module 3: Security Analysis, Risk Engine & Fix Verification",
            ],
            "ai_provider": settings.AI_PROVIDER,
        }

    @app.get("/health/dependencies", tags=["Health"])
    async def health_dependencies():
        # 1. Check Database
        db_healthy = False
        db_message = "Connected"
        try:
            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
                db_healthy = True
        except Exception as e:
            db_message = f"Database check failed: {str(e)}"

        # 2. Check Bruno CLI
        bruno_installed = bool(shutil.which(settings.BRUNO_CLI_PATH) or shutil.which("bru"))

        # 3. Check AI Provider status
        ai_status = f"Active ({settings.AI_PROVIDER})"
        if settings.AI_PROVIDER == "openai" and not settings.OPENAI_API_KEY:
            ai_status = "OpenAI key not configured; falling back to deterministic engine"

        return {
            "status": "healthy" if db_healthy else "degraded",
            "dependencies": {
                "database": {"healthy": db_healthy, "message": db_message},
                "ai_provider": {"configured_provider": settings.AI_PROVIDER, "status": ai_status},
                "bruno_cli": {
                    "available": bruno_installed,
                    "cli_path": settings.BRUNO_CLI_PATH,
                    "fallback_async_runner_active": True,
                },
            },
        }

    # Mount API v1
    app.include_router(api_v1_router, prefix=settings.API_V1_STR)

    # Mount Local Demo Target API
    app.mount("/demo", demo_app)

    return app


app = create_application()
