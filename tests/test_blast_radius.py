from app.schemas.module3.observation import SecurityObservation
from app.services.analyzers.blast_radius_engine import BlastRadiusEngine


def test_blast_radius_reach_and_business_impact():
    engine = BlastRadiusEngine()
    obs = SecurityObservation(
        attack_id="ATK-BOLA",
        category="BOLA",
        endpoint="/patients/{patient_id}",
        method="GET",
        status="failed",
        actual_status=200,
        steps=[{"step": 1, "url": "http://localhost:8080/api/v1/patients/102"}],
    )

    blast = engine.analyze_blast_radius(obs, "BOLA / IDOR", "high")
    assert "10,000" in blast.estimated_reach or "All" in blast.estimated_reach
    assert blast.confidence >= 0.80
    assert blast.is_estimate is True

    impact = engine.analyze_business_impact(obs, "BOLA / IDOR", "high")
    assert "Data Exposure" in impact.impact_categories
    assert "confidential" in impact.confirmed_impact.lower()
    assert len(impact.potential_impact) > 0
