from app.schemas.module3_contract import Module3ResultExport, Module3AttackResultItem, Module3Evidence
from app.services.module2_adapter import Module2ResultAdapter


def test_module2_result_adapter_normalization():
    adapter = Module2ResultAdapter()

    export_contract = Module3ResultExport(
        contract_version="1.0.0",
        run_id="run-101",
        project_id="proj-202",
        target={"base_url": "http://localhost:8080/api/v1", "authorized": True},
        summary={"total_attacks": 2, "passed_attacks": 1, "failed_attacks": 1},
        attack_results=[
            Module3AttackResultItem(
                attack_id="ATK-001",
                status="failed",
                endpoint="/patients/{id}",
                method="GET",
                category="BOLA",
                severity="critical",
                priority="critical",
                expected={"status": 403},
                actual={"status": 200},
                evidence=Module3Evidence(
                    request_headers={"Authorization": "[REDACTED]"},
                    response_headers={"content-type": "application/json"},
                    response_body='{"id": "102", "diagnosis": "Confidential"}',
                    response_time_ms=25.0,
                    status_code_matched=False,
                ),
                steps=[{"step": 1, "url": "http://localhost:8080/api/v1/patients/102"}],
                objective="Access foreign patient file",
            )
        ]
    )

    observations = adapter.normalize_results(export_contract)
    assert len(observations) == 1
    obs = observations[0]
    assert obs.attack_id == "ATK-001"
    assert obs.category == "BOLA"
    assert obs.expected_status == 403
    assert obs.actual_status == 200
    assert "diagnosis" in obs.response_body
