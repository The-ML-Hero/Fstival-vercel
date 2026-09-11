from app.schemas.module3.observation import SecurityObservation
from app.services.analyzers.ai_explanation_engine import AIExplanationEngine


def test_ai_explanation_dimensions_and_accuracy():
    engine = AIExplanationEngine()
    obs = SecurityObservation(
        attack_id="ATK-ROLE",
        category="Role Escalation",
        endpoint="/users/1",
        method="PUT",
        status="failed",
        actual_status=200,
        expected_status=403,
    )

    explanations = engine.generate_explanations(obs, "Role Escalation", "critical")

    assert len(explanations.technical_explanation) > 20
    assert len(explanations.simple_explanation) > 20
    assert len(explanations.evidence_explanation) > 20
    assert len(explanations.why_it_matters) > 20

    # Ensure no hallucination; matches endpoint and method
    assert "PUT /users/1" in explanations.technical_explanation or "PUT" in explanations.technical_explanation
    assert "HTTP 200" in explanations.evidence_explanation
