from app.schemas.execution_plan import AttackScenario, AttackScenarioStep
from app.services.simulation.workflow_executor import WorkflowExecutor


def test_workflow_out_of_order_scenario_generation():
    executor = WorkflowExecutor()

    base_scenario = AttackScenario(
        scenario_id="SCENARIO-WF-001",
        attack_id="ATK-WF-001",
        category="Business Logic",
        endpoint="/orders",
        method="POST",
        objective="Normal workflow",
        steps=[
            AttackScenarioStep(step_number=1, step_name="create_order", method="POST", path="/orders", body={"items": ["A"]}),
            AttackScenarioStep(step_number=2, step_name="pay_order", method="POST", path="/orders/101/pay", body={"amount": 50}),
            AttackScenarioStep(step_number=3, step_name="refund_order", method="POST", path="/orders/101/refund"),
        ],
        expected_secure_behavior="400 Bad Request on out-of-order",
        expected_status=400,
    )

    # Reorder: Refund (index 2) before Payment (index 1)
    altered = executor.create_out_of_order_scenario(
        base_scenario=base_scenario,
        reversed_step_indices=[2, 1],
        suffix="REFUND-BEFORE-PAY"
    )

    assert altered.attack_id == "ATK-WF-001-REFUND-BEFORE-PAY"
    assert altered.is_adaptive is True
    assert len(altered.steps) == 2
    assert "refund" in altered.steps[0].step_name
    assert "pay" in altered.steps[1].step_name
    assert altered.steps[0].expected_status == 400
