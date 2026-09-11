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


class OpenAIAdapter(BaseAIProvider):
    """
    OpenAI adapter for API Guardian.
    Sends sanitized API descriptions and requests structured Pydantic-compliant JSON.
    """

    def __init__(self):
        self.api_key = settings.OPENAI_API_KEY
        self.model = settings.OPENAI_MODEL
        self.base_url = settings.OPENAI_BASE_URL.rstrip("/")
        self.timeout = settings.OPENAI_TIMEOUT_SECONDS
        self.fallback = FallbackAIProvider()

    async def analyze_api(self, context: Dict[str, Any]) -> AIAnalysisResult:
        if not self.api_key:
            logger.warning("OpenAI API key not configured; falling back to deterministic AI provider.")
            return await self.fallback.analyze_api(context)

        # Sanitize payload to guarantee no secret tokens or keys are sent to external LLMs
        sanitized_context = sanitize_payload(context)

        system_prompt = (
            "You are API Guardian, an elite automated API security testing and vulnerability planning engine. "
            "Your objective is to analyze the provided API specification context (endpoints, parameters, schemas, auth, roles, workflows) "
            "and produce an intelligent, prioritized attack plan across 10 security categories: "
            "1. Authentication, 2. Authorization, 3. BOLA / IDOR, 4. Role Escalation, 5. Input Validation, "
            "6. Parameter Tampering, 7. Rate-Limit Testing, 8. HTTP Method Abuse, 9. Information Exposure, 10. Business Logic. "
            "You MUST respond ONLY with a valid JSON object strictly conforming to the following JSON schema."
        )

        user_prompt = f"Analyze the following API context and generate an attack plan:\n\n{json.dumps(sanitized_context, indent=2)}"

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        payload = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.2,
        }

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    headers=headers,
                    json=payload
                )

            if response.status_code != 200:
                logger.error(f"OpenAI API error ({response.status_code}): {response.text}")
                raise AIProviderError(f"OpenAI returned HTTP {response.status_code}: {response.text}")

            res_json = response.json()
            content_str = res_json["choices"][0]["message"]["content"]
            parsed_dict = json.loads(content_str)
            return AIAnalysisResult.model_validate(parsed_dict)

        except Exception as e:
            logger.error(f"OpenAI adapter failed ({str(e)}). Falling back to deterministic engine.")
            return await self.fallback.analyze_api(context)
