import pytest
from app.services.ai.factory import get_ai_provider
from app.services.ai.fallback_adapter import FallbackAIProvider
from app.services.ai.openai_adapter import OpenAIAdapter
from app.services.ai.ollama_adapter import OllamaAdapter


@pytest.mark.asyncio
async def test_fallback_ai_provider_direct():
    provider = get_ai_provider("fallback")
    assert isinstance(provider, FallbackAIProvider)
    res = await provider.analyze_api({"endpoints": [], "roles": [], "resources": [], "workflows": []})
    assert res.summary is not None
    assert isinstance(res.attack_hypotheses, list)


@pytest.mark.asyncio
async def test_openai_adapter_fallback_on_empty_key():
    provider = OpenAIAdapter()
    provider.api_key = ""
    # Should fall back cleanly without raising exception
    res = await provider.analyze_api({"endpoints": [], "roles": [], "resources": [], "workflows": []})
    assert res is not None
    assert len(res.summary) > 0


@pytest.mark.asyncio
async def test_ollama_adapter_fallback_on_unreachable_host():
    provider = OllamaAdapter()
    provider.base_url = "http://invalid-unreachable-ollama-host:9999"
    # Should fall back cleanly without raising exception
    res = await provider.analyze_api({"endpoints": [], "roles": [], "resources": [], "workflows": []})
    assert res is not None
    assert len(res.summary) > 0
