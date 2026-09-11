from typing import Any, Optional


class APIGuardianException(Exception):
    """Base exception for all API Guardian errors."""
    def __init__(self, message: str, details: Optional[Any] = None):
        super().__init__(message)
        self.message = message
        self.details = details


class SpecParsingError(APIGuardianException):
    """Raised when OpenAPI / Swagger spec fails parsing or validation."""
    pass


class ProjectNotFoundError(APIGuardianException):
    """Raised when the specified project ID does not exist."""
    pass


class TargetNotAuthorizedError(APIGuardianException):
    """Raised when operation requires target authorization and it is false."""
    pass


class AnalysisError(APIGuardianException):
    """Raised when an error occurs during the analysis pipeline."""
    pass


class AIProviderError(APIGuardianException):
    """Raised when the AI provider fails to generate a response."""
    pass
