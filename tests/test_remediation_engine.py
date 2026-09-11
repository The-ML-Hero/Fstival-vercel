from app.schemas.module3.observation import SecurityObservation
from app.services.analyzers.remediation_engine import RemediationEngine


def test_remediation_recommendations_and_pseudocode():
    engine = RemediationEngine()
    obs = SecurityObservation(
        attack_id="ATK-BOLA",
        category="BOLA",
        endpoint="/patients/{id}",
        method="GET",
        status="failed",
    )

    remediation = engine.generate_remediation(obs, "BOLA / IDOR")

    assert len(remediation.what_to_change) > 10
    assert len(remediation.why) > 10
    assert len(remediation.secure_design_principle) > 5
    assert len(remediation.example_pseudocode) > 20
    assert "current_user" in remediation.example_pseudocode
