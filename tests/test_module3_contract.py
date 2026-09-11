from datetime import datetime, timezone
from app.schemas.module3_contract import (
    Module3ResultExport,
    Module3AttackResultItem,
    Module3Evidence,
)


def test_module3_result_export_contract():
    export_payload = Module3ResultExport(
        contract_version="1.0.0",
        exported_at=datetime.now(timezone.utc),
        run_id="run-uuid-101",
        project_id="proj-uuid-202",
        target={
            "base_url": "http://localhost:8080/api/v1",
            "environment": "local",
            "authorized": True
        },
        summary={
            "total_attacks": 5,
            "passed_attacks": 4,
            "failed_attacks": 1,
            "error_attacks": 0,
            "status": "completed"
        },
        attack_results=[
            Module3AttackResultItem(
                attack_id="ATK-001",
                status="failed",  # Security test failed -> vulnerability present
                endpoint="/patients/{id}",
                method="GET",
                category="BOLA",
                severity="critical",
                priority="critical",
                expected={"status": 403},
                actual={"status": 200},
                evidence=Module3Evidence(
                    request_headers={"Authorization": "[REDACTED_AUTH_CREDENTIAL]"},
                    response_headers={"content-type": "application/json"},
                    response_body='{"id": "102", "name": "Confidential Record"}',
                    response_time_ms=32.5,
                    status_code_matched=False
                ),
                steps=[
                    {
                        "step": 1,
                        "name": "fetch_patient_102",
                        "method": "GET",
                        "url": "http://localhost:8080/api/v1/patients/102",
                        "status_code": 200,
                        "duration_ms": 32.5
                    }
                ],
                parent_attack_id=None,
                is_adaptive=False,
                reproducible=True,
                objective="Access unauthorized patient file",
                reason="Object ID in path lacks ownership validation."
            )
        ]
    )

    # Test serialization / deserialization
    json_str = export_payload.model_dump_json()
    assert "ATK-001" in json_str
    assert "BOLA" in json_str
    assert "Confidential Record" in json_str

    validated = Module3ResultExport.model_validate_json(json_str)
    assert validated.run_id == "run-uuid-101"
    assert validated.attack_results[0].expected["status"] == 403
    assert validated.attack_results[0].actual["status"] == 200
