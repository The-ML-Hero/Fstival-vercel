from typing import Any, Dict, List, Union
from app.core.config import settings
from app.core.exceptions import TargetNotAuthorizedError

SENSITIVE_FIELD_NAMES = {
    "password",
    "passwd",
    "secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "auth_token",
    "token",
    "private_key",
    "client_secret",
    "credential",
    "credentials",
    "ssn",
    "credit_card",
    "cvv",
}


def sanitize_payload(data: Any) -> Any:
    """
    Recursively scrubs sensitive keys and values from dictionaries/lists
    before sending data to AI providers, saving to logs, or exporting.
    """
    if isinstance(data, dict):
        sanitized: Dict[str, Any] = {}
        for key, value in data.items():
            lower_key = str(key).lower().replace("-", "_")
            if any(sensitive in lower_key for sensitive in SENSITIVE_FIELD_NAMES):
                sanitized[key] = "[REDACTED_SECRET]"
            else:
                sanitized[key] = sanitize_payload(value)
        return sanitized
    elif isinstance(data, list):
        return [sanitize_payload(item) for item in data]
    elif isinstance(data, str):
        # Basic check for JWT-like strings or Bearer headers
        if data.lower().startswith("bearer ") or len(data) > 64 and "." in data and data.count(".") == 2:
            return "[REDACTED_TOKEN]"
        return data
    return data


def check_target_authorization(target_authorized: bool, target_base_url: str | None = None) -> None:
    """
    Validates whether the target environment is explicitly authorized.
    Defensive safe-by-default behavior.
    """
    if settings.REQUIRE_TARGET_AUTHORIZATION_FOR_ANALYSIS and not target_authorized:
        raise TargetNotAuthorizedError(
            f"Target {target_base_url or 'API'} is not marked as authorized. "
            "Set target_authorized=True before proceeding with analysis."
        )
