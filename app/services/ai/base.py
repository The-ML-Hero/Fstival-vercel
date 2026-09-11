from abc import ABC, abstractmethod
from typing import Any, Dict
from app.schemas.ai_models import AIAnalysisResult


class BaseAIProvider(ABC):
    """
    Abstract interface for provider-independent AI analysis in API Guardian.
    Adapters implement this contract to generate structured security hypotheses.
    """

    @abstractmethod
    async def analyze_api(self, context: Dict[str, Any]) -> AIAnalysisResult:
        """
        Takes a sanitized context dictionary describing the API
        (endpoints, parameters, schemas, roles, resources, workflows)
        and returns a Pydantic-validated AIAnalysisResult.
        """
        pass
