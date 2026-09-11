from app.core.config import settings
from app.core.logging import logger
from app.services.ai.base import BaseAIProvider
from app.services.ai.fallback_adapter import FallbackAIProvider
from app.services.ai.openai_adapter import OpenAIAdapter
from app.services.ai.ollama_adapter import OllamaAdapter


def get_ai_provider(provider_type: str | None = None) -> BaseAIProvider:
    """
    Factory method to instantiate the appropriate AI provider adapter based on configuration.
    """
    selected = provider_type or settings.AI_PROVIDER.lower()

    if selected == "openai":
        return OpenAIAdapter()
    elif selected == "ollama":
        return OllamaAdapter()
    elif selected == "fallback":
        return FallbackAIProvider()
    else:
        logger.warning(f"Unrecognized AI provider '{selected}'. Defaulting to deterministic fallback engine.")
        return FallbackAIProvider()
