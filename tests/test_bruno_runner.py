import pytest
from httpx import AsyncClient, ASGITransport
from app.demo_api.server import demo_app
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.services.bruno.runner import BrunoRunner


@pytest.mark.asyncio
async def test_bruno_runner_executes_scenario_against_demo_api():
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://testdemo") as test_client:
        runner = BrunoRunner()
        target = TargetConfig(base_url="http://testdemo", authorized=True)

        # Test BOLA scenario on demo patient endpoint (fails security check if 200 is returned when 403 was expected)
        scenario = AttackScenario(
            scenario_id="SCENARIO-ATK-001",
            attack_id="ATK-001",
            category="BOLA",
            endpoint="/patients/{id}",
            method="GET",
            objective="Access patient 102",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="fetch_patient_102",
                    method="GET",
                    path="/patients/102",
                    expected_status=403,  # Secure API must return 403
                )
            ],
            expected_secure_behavior="403 Forbidden",
            expected_status=403,
            role_required="user",
        )

        exec_summary = await runner.execute_scenario(scenario, target, test_client)

        # Since demo_app allows access without ownership check (returns 200 instead of 403),
        # the security test correctly identifies the vulnerability (status = "failed" assertion)
        assert exec_summary.actual_status == 200
        assert exec_summary.expected_status == 403
        assert exec_summary.status == "failed"
        assert exec_summary.duration_ms >= 0.0
        assert len(exec_summary.step_results) == 1
        assert "diagnosis" in exec_summary.step_results[0]["response_body"]
