from app.services.module1_adapter import Module1AttackPlanAdapter


def test_adapter_parses_module1_attack_plan():
    adapter = Module1AttackPlanAdapter()
    sample_plan = {
        "attack_plan": [
            {
                "attack_id": "ATK-001",
                "type": "BOLA",
                "endpoint": "/patients/{patient_id}",
                "method": "GET",
                "objective": "Access unauthorized patient file",
                "preconditions": ["User B authenticated"],
                "steps": ["1. Replace ID with target ID"],
                "expected_secure_behavior": "403 Forbidden",
                "severity": "critical",
                "priority": "critical",
                "mutations": [
                    {
                        "parameter_name": "patient_id",
                        "parameter_location": "path",
                        "mutation_type": "cross_tenant_id",
                        "payload_sample": "PATIENT-999"
                    }
                ]
            },
            {
                "attack_id": "ATK-002",
                "type": "Authentication",
                "endpoint": "/admin/settings",
                "method": "POST",
                "objective": "Test without token",
                "expected_secure_behavior": "401 Unauthorized",
                "mutations": []
            }
        ]
    }

    scenarios = adapter.parse_attack_plan(sample_plan)
    assert len(scenarios) == 2

    # Scenario 1 (BOLA)
    s1 = scenarios[0]
    assert s1.attack_id == "ATK-001"
    assert s1.category == "BOLA"
    assert s1.expected_status == 403
    assert len(s1.steps) == 1
    assert "PATIENT-999" in s1.steps[0].path

    # Scenario 2 (Auth)
    s2 = scenarios[1]
    assert s2.attack_id == "ATK-002"
    assert s2.expected_status == 401
    assert s2.role_required == "anonymous"
