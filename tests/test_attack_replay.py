import pytest
from httpx import AsyncClient, ASGITransport
from app.demo_api.server import demo_app
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.services.bruno.runner import BrunoRunner


@pytest.mark.asyncio
async def test_attack_replay_reproducibility():
    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://testdemo") as test_client:
        runner = BrunoRunner()
        target = TargetConfig(base_url="http://testdemo", authorized=True)

        scenario = AttackScenario(
            scenario_id="SCENARIO-REPLAY-1",
            attack_id="ATK-REPLAY-1",
            category="BOLA",
            endpoint="/orders/101",
            method="GET",
            objective="Replay BOLA invoice access",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="get_order_101",
                    method="GET",
                    path="/orders/101",
                    expected_status=403,
                )
            ],
            expected_secure_behavior="403 Forbidden",
            expected_status=403,
        )

        # Initial run
        run_1 = await runner.execute_scenario(scenario, target, test_client)
        assert run_1.actual_status == 200

        # Replay run
        run_2 = await runner.execute_scenario(scenario, target, test_client)
        assert run_2.actual_status == 200

        # Behavior is reproduced
        assert run_1.actual_status == run_2.actual_status
        assert run_1.status == run_2.status
