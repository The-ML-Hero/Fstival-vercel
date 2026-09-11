from typing import Any, List, Literal
from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "API Guardian — AI-Powered API Security & Attack Simulation Platform"
    APP_ENV: str = "development"
    DEBUG: bool = True
    LOG_LEVEL: str = "INFO"
    API_V1_STR: str = "/api/v1"

    # CORS Allowed Origins
    ALLOWED_ORIGINS: List[str] = [
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "*",
    ]

    # Database (Default uses SQLite async; configure PostgreSQL for production)
    DATABASE_URL: str = "sqlite+aiosqlite:///./api_guardian.db"

    # AI Provider: "fallback", "openai", "ollama"
    AI_PROVIDER: Literal["fallback", "openai", "ollama"] = "fallback"

    # OpenAI Settings
    OPENAI_API_KEY: str = ""
    OPENAI_MODEL: str = "gpt-4o-mini"
    OPENAI_BASE_URL: str = "https://api.openai.com/v1"
    OPENAI_TIMEOUT_SECONDS: float = 60.0

    # Ollama Settings
    OLLAMA_BASE_URL: str = "http://localhost:11434"
    OLLAMA_MODEL: str = "llama3.2"
    OLLAMA_TIMEOUT_SECONDS: float = 90.0

    # Scoring Weights for Attack Prioritization
    PRIORITY_WEIGHT_SEVERITY: float = Field(default=0.40, ge=0.0, le=1.0)
    PRIORITY_WEIGHT_EXPLOITABILITY: float = Field(default=0.30, ge=0.0, le=1.0)
    PRIORITY_WEIGHT_CONFIDENCE: float = Field(default=0.15, ge=0.0, le=1.0)
    PRIORITY_WEIGHT_IMPACT: float = Field(default=0.15, ge=0.0, le=1.0)

    # Security Settings
    REQUIRE_TARGET_AUTHORIZATION_FOR_ANALYSIS: bool = False
    REQUIRE_TARGET_AUTHORIZATION_FOR_EXECUTION: bool = True
    MASK_SECRETS_IN_LOGS: bool = True

    # Module 2 Execution Settings
    BRUNO_CLI_PATH: str = "bru"  # Path to bru or npx @usebruno/cli
    GENERATED_COLLECTIONS_DIR: str = "./generated"
    MAX_ADAPTIVE_DEPTH: int = 3
    MAX_ADAPTIVE_REQUESTS_PER_ATTACK: int = 5
    MAX_RATE_LIMIT_TEST_REQUESTS: int = 20
    EXECUTION_TIMEOUT_SECONDS: float = 120.0
    REQUEST_TIMEOUT_SECONDS: float = 10.0

    # Multi-Role Simulation Tokens (configurable via environment)
    TEST_USERS_USER_TOKEN: str = "mock-user-jwt-token-alpha"
    TEST_USERS_STAFF_TOKEN: str = "mock-staff-jwt-token-beta"
    TEST_USERS_ADMIN_TOKEN: str = "mock-admin-jwt-token-gamma"

    @field_validator(
        "DEBUG",
        "OPENAI_TIMEOUT_SECONDS",
        "OLLAMA_TIMEOUT_SECONDS",
        "PRIORITY_WEIGHT_SEVERITY",
        "PRIORITY_WEIGHT_EXPLOITABILITY",
        "PRIORITY_WEIGHT_CONFIDENCE",
        "PRIORITY_WEIGHT_IMPACT",
        "REQUIRE_TARGET_AUTHORIZATION_FOR_ANALYSIS",
        "REQUIRE_TARGET_AUTHORIZATION_FOR_EXECUTION",
        "MASK_SECRETS_IN_LOGS",
        "MAX_ADAPTIVE_DEPTH",
        "MAX_ADAPTIVE_REQUESTS_PER_ATTACK",
        "MAX_RATE_LIMIT_TEST_REQUESTS",
        "EXECUTION_TIMEOUT_SECONDS",
        "REQUEST_TIMEOUT_SECONDS",
        mode="before",
    )
    @classmethod
    def empty_str_to_default(cls, v: Any, info):
        if isinstance(v, str) and v.strip() == "":
            return cls.model_fields[info.field_name].get_default(call_default_factory=True)
        return v


settings = Settings()
