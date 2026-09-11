from app.schemas.execution_plan import AttackScenario, AttackScenarioStep
from app.services.bruno.runner import ExecutionResultSummary
from app.services.simulation.adaptive_engine import AdaptiveAttackEngine


def test_adaptive_engine_triggers_followups_on_bola_vulnerability():
    engine = AdaptiveAttackEngine(max_depth=3, max_requests_per_attack=3)

    scenario = AttackScenario(
        scenario_id="SCENARIO-BOLA-1",
        attack_id="ATK-BOLA-1",
        category="BOLA",
        endpoint="/patients/{id}",
        method="GET",
        objective="Initial BOLA test on ID 101",
        steps=[
            AttackScenarioStep(
                step_number=1,
                step_name="get_patient_101",
                method="GET",
                path="/patients/101",
                expected_status=403,
            )
        ],
        expected_secure_behavior="403 Forbidden",
        expected_status=403,
    )

    # Simulate vulnerability: API returned 200 OK
    exec_result = ExecutionResultSummary(
        scenario=scenario,
        status="failed",
        actual_status=200,
        expected_status=403,
        duration_ms=45.0,
        step_results=[]
    )

    followups = engine.evaluate_and_generate_followup(exec_result, current_depth=1)

    assert len(followups) == 3
    # Check that followups test adjacent IDs 102, 103, 104
    assert "/patients/102" in followups[0].steps[0].path
    assert "/patients/103" in followups[1].steps[0].path
    assert "/patients/104" in followups[2].steps[0].path
    for f in followups:
        assert f.is_adaptive is True
        assert f.parent_attack_id == "ATK-BOLA-1"


def test_adaptive_engine_halts_at_max_depth():
    engine = AdaptiveAttackEngine(max_depth=2)
    scenario = AttackScenario(
        scenario_id="SCENARIO-BOLA-1",
        attack_id="ATK-BOLA-1",
        category="BOLA",
        endpoint="/patients/{id}",
        method="GET",
        objective="BOLA",
        steps=[AttackScenarioStep(step_number=1, step_name="step", method="GET", path="/patients/101")],
        expected_secure_behavior="403",
        expected_status=403,
    )
    exec_result = ExecutionResultSummary(
        scenario=scenario,
        status="failed",
        actual_status=200,
        expected_status=403,
        duration_ms=45.0,
        step_results=[]
    )

    # At depth 3 (exceeding max_depth 2), no followups generated
    followups = engine.evaluate_and_generate_followup(exec_result, current_depth=3)
    assert len(followups) == 0
