import json
from typing import Any, Dict
import httpx

from app.core.config import settings
from app.core.exceptions import AIProviderError
from app.core.logging import logger
from app.core.security import sanitize_payload
from app.schemas.ai_models import AIAnalysisResult
from app.services.ai.base import BaseAIProvider
from app.services.ai.fallback_adapter import FallbackAIProvider


class OllamaAdapter(BaseAIProvider):
    """
    Ollama adapter for local model execution (e.g., llama3.2, mistral, deepseek-coder).
    Enforces structured JSON generation.
    """

    def __init__(self):
        self.base_url = settings.OLLAMA_BASE_URL.rstrip("/")
        self.model = settings.OLLAMA_MODEL
        self.timeout = settings.OLLAMA_TIMEOUT_SECONDS
        self.fallback = FallbackAIProvider()

    async def analyze_api(self, context: Dict[str, Any]) -> AIAnalysisResult:
        sanitized_context = sanitize_payload(context)

        system_prompt = (
            "You are API Guardian, an automated API security testing analysis platform. "
            "Analyze the given API context and output an attack plan in strict JSON."
        )

        user_prompt = f"API Context:\n{json.dumps(sanitized_context, indent=2)}"

        payload = {
            "model": self.model,
            "system": system_prompt,
            "prompt": user_prompt,
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.2},
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/api/generate",
                    json=payload
                )

            if response.status_code != 200:
                logger.error(f"Ollama API error ({response.status_code}): {response.text}")
                raise AIProviderError(f"Ollama returned HTTP {response.status_code}")

            res_json = response.json()
            content_str = res_json.get("response", "{}")
            parsed_dict = json.loads(content_str)
            return AIAnalysisResult.model_validate(parsed_dict)

        except Exception as e:
            logger.warning(f"Ollama provider failed or unreachable ({str(e)}). Falling back to deterministic engine.")
            return await self.fallback.analyze_api(context)
