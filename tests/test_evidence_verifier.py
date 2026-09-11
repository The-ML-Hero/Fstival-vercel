from app.schemas.module3.observation import SecurityObservation
from app.services.analyzers.evidence_verifier import EvidenceVerifier


def test_evidence_verifier_confirmed_sensitive_payload():
    verifier = EvidenceVerifier()
    obs = SecurityObservation(
        attack_id="ATK-001",
        category="BOLA",
        endpoint="/patients/102",
        method="GET",
        status="failed",
        expected_status=403,
        actual_status=200,
        response_body='{"id": "102", "name": "Patient X", "diagnosis": "Hypertension", "ssn": "123-45-6789"}',
    )
    result = verifier.verify(obs)
    assert result.status == "confirmed"
    assert result.confidence >= 0.90
    assert result.data_sensitivity == "high"
    assert result.is_vulnerable is True


def test_evidence_verifier_false_positive_html_error_page():
    verifier = EvidenceVerifier()
    obs = SecurityObservation(
        attack_id="ATK-002",
        category="BOLA",
        endpoint="/patients/999",
        method="GET",
        status="failed",
        expected_status=403,
        actual_status=200,  # 200 returned by server, but contains 404 page
        response_body='<!DOCTYPE html><html><head><title>404 Not Found</title></head><body>Page does not exist</body></html>',
    )
    result = verifier.verify(obs)
    assert result.status == "false-positive"
    assert result.is_vulnerable is False


def test_evidence_verifier_secure_passed_attack():
    verifier = EvidenceVerifier()
    obs = SecurityObservation(
        attack_id="ATK-003",
        category="Authentication",
        endpoint="/admin/settings",
        method="GET",
        status="passed",
        expected_status=401,
        actual_status=401,
    )
    result = verifier.verify(obs)
    assert result.status == "false-positive"
    assert result.is_vulnerable is False
