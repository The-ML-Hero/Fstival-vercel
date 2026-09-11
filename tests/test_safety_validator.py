import pytest
from app.core.exceptions import TargetNotAuthorizedError
from app.schemas.execution_plan import TargetConfig
from app.services.safety.safety_validator import SafetyValidator


def test_safety_validator_rejects_unauthorized_target():
    validator = SafetyValidator()
    target = TargetConfig(
        base_url="http://localhost:8080",
        authorized=False
    )
    with pytest.raises(TargetNotAuthorizedError):
        validator.validate_target(target)


def test_safety_validator_accepts_authorized_local_target():
    validator = SafetyValidator()
    target = TargetConfig(
        base_url="http://localhost:8080/api/v1",
        authorized=True,
        environment="local"
    )
    is_local, warnings = validator.validate_target(target)
    assert is_local is True
    assert len(warnings) == 0


def test_safety_validator_warns_on_non_local_target():
    validator = SafetyValidator()
    target = TargetConfig(
        base_url="https://api.external-enterprise-domain.com",
        authorized=True,
        environment="authorized"
    )
    is_local, warnings = validator.validate_target(target)
    assert is_local is False
    assert len(warnings) > 0
    assert "CAUTION" in warnings[0]


def test_safety_validator_neutralizes_destructive_payloads():
    validator = SafetyValidator()
    clean_payload = {"name": "Test User", "age": 30}
    sanitized_clean = validator.sanitize_scenario_payload(clean_payload)
    assert sanitized_clean == clean_payload

    dangerous_payload = {"query": "DROP TABLE users; --", "note": "rm -rf /"}
    sanitized_danger = validator.sanitize_scenario_payload(dangerous_payload)
    assert sanitized_danger["query"] == "[NEUTRALIZED_DESTRUCTIVE_PAYLOAD]"
    assert sanitized_danger["note"] == "[NEUTRALIZED_DESTRUCTIVE_PAYLOAD]"
