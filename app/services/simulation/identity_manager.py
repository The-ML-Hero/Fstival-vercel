import re
from typing import Dict, Optional
from app.core.config import settings


class IdentityManager:
    """
    Multi-Role Identity Simulator for Module 2.
    Injects role-based credentials (user, staff, admin, anonymous) without hardcoded secrets.
    """

    def __init__(self, custom_tokens: Optional[Dict[str, str]] = None):
        self.tokens: Dict[str, str] = {
            "anonymous": "",
            "user": settings.TEST_USERS_USER_TOKEN,
            "staff": settings.TEST_USERS_STAFF_TOKEN,
            "admin": settings.TEST_USERS_ADMIN_TOKEN,
        }
        if custom_tokens:
            for role, token in custom_tokens.items():
                self.tokens[role.lower()] = token

    def get_token_for_role(self, role: str) -> Optional[str]:
        """Retrieves authentication token for the specified role tier."""
        normalized = (role or "user").lower().strip()
        return self.tokens.get(normalized, self.tokens.get("user"))

    def inject_auth_headers(
        self,
        headers: Dict[str, str],
        role: str = "user"
    ) -> Dict[str, str]:
        """
        Injects Authorization header if not already provided and role is not anonymous.
        """
        updated = dict(headers)
        # If caller already specified Authorization or role is anonymous, return as-is
        if "Authorization" in updated or "authorization" in updated:
            return updated

        token = self.get_token_for_role(role)
        if token:
            updated["Authorization"] = f"Bearer {token}"

        return updated

    def redact_sensitive_headers(self, headers: Dict[str, str]) -> Dict[str, str]:
        """
        Redacts sensitive tokens and passwords before logging or saving to database/evidence.
        """
        redacted: Dict[str, str] = {}
        for k, v in headers.items():
            k_lower = k.lower()
            if any(s in k_lower for s in ["auth", "token", "secret", "cookie", "key"]):
                redacted[k] = "[REDACTED_AUTH_CREDENTIAL]"
            else:
                redacted[k] = v
        return redacted
