import re
from urllib.parse import urlparse
from typing import Any, Dict, List, Tuple
from app.core.exceptions import TargetNotAuthorizedError
from app.core.logging import logger
from app.schemas.execution_plan import TargetConfig

# Prohibited destructive payload markers
DESTRUCTIVE_MARKERS = [
    re.compile(r'(?i)\b(?:DROP\s+DATABASE|DROP\s+TABLE|TRUNCATE\s+TABLE)\b'),
    re.compile(r'(?i)\b(?:rm\s+-rf|format\s+[a-z]:|shutdown|init\s+0)\b'),
    re.compile(r'(?i)\b(?:wget\s+http|curl\s+http.*\|\s*sh|bash\s+-i)\b'),
]


class SafetyValidator:
    """
    Mandatory Defensive Safety Layer for Module 2.
    Ensures tests are ONLY executed against explicitly authorized targets,
    warns on non-local targets, and filters destructive exploitation attempts.
    """

    def validate_target(self, target: TargetConfig) -> Tuple[bool, List[str]]:
        """
        Validates target authorization and environment.
        Raises TargetNotAuthorizedError if authorized is False.
        Returns (is_local, warnings).
        """
        warnings: List[str] = []

        if not target.authorized:
            raise TargetNotAuthorizedError(
                f"Execution rejected: Target base URL '{target.base_url}' is not marked as authorized. "
                "Set authorized=True to permit controlled security testing."
            )

        parsed = urlparse(target.base_url)
        hostname = (parsed.hostname or "").lower()

        # Check local / private network boundary
        is_local = (
            hostname in {"localhost", "127.0.0.1", "0.0.0.0", "::1"}
            or hostname.endswith(".local")
            or hostname.endswith(".internal")
            or hostname.startswith("192.168.")
            or hostname.startswith("10.")
            or (hostname.startswith("172.") and 16 <= int(hostname.split(".")[1] or 0) <= 31)
        )

        if not is_local:
            msg = (
                f"CAUTION: Target '{target.base_url}' is an external/non-local host. "
                "Ensure written authorization and strict scope boundaries are in place."
            )
            logger.warning(msg)
            warnings.append(msg)

        return is_local, warnings

    def sanitize_scenario_payload(self, body: Any) -> Any:
        """
        Scans and strips destructive payload markers from test scenario payloads.
        """
        if isinstance(body, str):
            for pattern in DESTRUCTIVE_MARKERS:
                if pattern.search(body):
                    logger.warning(f"Destructive payload pattern detected and neutralized: {pattern.pattern}")
                    return "[NEUTRALIZED_DESTRUCTIVE_PAYLOAD]"
            return body
        elif isinstance(body, dict):
            return {k: self.sanitize_scenario_payload(v) for k, v in body.items()}
        elif isinstance(body, list):
            return [self.sanitize_scenario_payload(item) for item in body]
        return body
