import pytest
from httpx import AsyncClient, ASGITransport
from app.demo_api.server import demo_app
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.services.bruno.runner import BrunoRunner


@pytest.mark.asyncio
async def test_live_simulation_vulnerabilities_on_demo_api():
    from app.demo_api import server as demo_server
    demo_server.PATCH_VULNERABILITIES = False

    transport = ASGITransport(app=demo_app)
    async with AsyncClient(transport=transport, base_url="http://testdemo") as test_client:
        runner = BrunoRunner()
        target = TargetConfig(base_url="http://testdemo", authorized=True)

        # 1. BOLA Vulnerability Test on /orders/{id}
        bola_scenario = AttackScenario(
            scenario_id="SCENARIO-BOLA-DEMO",
            attack_id="ATK-BOLA-DEMO",
            category="BOLA",
            endpoint="/orders/102",
            method="GET",
            objective="Attempt reading Bob's order as Alice",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="fetch_order_102",
                    method="GET",
                    path="/orders/102",
                    expected_status=403,  # Should be forbidden on secure API
                )
            ],
            expected_secure_behavior="403 Forbidden",
            expected_status=403,
            role_required="user"
        )
        res_bola = await runner.execute_scenario(bola_scenario, target, test_client)
        # Demo API has BOLA flaw (returns 200), so the security test assertion fails
        assert res_bola.actual_status == 200
        assert res_bola.status == "failed"

        # 2. Broken Authentication on /admin/users
        admin_auth_scenario = AttackScenario(
            scenario_id="SCENARIO-ADMIN-AUTH",
            attack_id="ATK-ADMIN-AUTH",
            category="Authentication",
            endpoint="/admin/users",
            method="GET",
            objective="Attempt listing users unauthenticated",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="unauthenticated_admin_fetch",
                    method="GET",
                    path="/admin/users",
                    expected_status=401,
                )
            ],
            expected_secure_behavior="401 Unauthorized",
            expected_status=401,
            role_required="anonymous"
        )
        res_admin = await runner.execute_scenario(admin_auth_scenario, target, test_client)
        # Demo API has broken auth (returns 200), test flags vulnerability
        assert res_admin.actual_status == 200
        assert res_admin.status == "failed"

        # 3. Role Escalation / Mass Assignment on /users/{id}
        role_escalation_scenario = AttackScenario(
            scenario_id="SCENARIO-ROLE-ESC",
            attack_id="ATK-ROLE-ESC",
            category="Role Escalation",
            endpoint="/users/1",
            method="PUT",
            objective="Attempt self-assigning admin role",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="put_role_admin",
                    method="PUT",
                    path="/users/1",
                    body={"role": "admin"},
                    expected_status=403,
                )
            ],
            expected_secure_behavior="403 Forbidden",
            expected_status=403,
            role_required="user"
        )
        res_role = await runner.execute_scenario(role_escalation_scenario, target, test_client)
        assert res_role.actual_status == 200
        assert res_role.status == "failed"

        # 4. Negative Price / Financial Tampering on /orders/{id}/pay
        pay_tamper_scenario = AttackScenario(
            scenario_id="SCENARIO-PAY-TAMPER",
            attack_id="ATK-PAY-TAMPER",
            category="Parameter Tampering",
            endpoint="/orders/101/pay",
            method="POST",
            objective="Submit negative payment amount",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="pay_negative_amount",
                    method="POST",
                    path="/orders/101/pay",
                    body={"amount": -50.0},
                    expected_status=400,
                )
            ],
            expected_secure_behavior="400 Bad Request",
            expected_status=400,
            role_required="user"
        )
        res_pay = await runner.execute_scenario(pay_tamper_scenario, target, test_client)
        # Demo API accepts negative amount and returns 200
        assert res_pay.actual_status == 200
        assert res_pay.status == "failed"

        # 5. Rate Limit Occurrence on /rate-limit-test
        rate_limit_scenario = AttackScenario(
            scenario_id="SCENARIO-RATE-LIMIT",
            attack_id="ATK-RATE-LIMIT",
            category="Rate-Limit Testing",
            endpoint="/rate-limit-test",
            method="GET",
            objective="Send consecutive requests until 429 is triggered",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="get_rate_limit",
                    method="GET",
                    path="/rate-limit-test",
                    expected_status=429,
                )
            ],
            expected_secure_behavior="429 Too Many Requests",
            expected_status=429,
            role_required="user"
        )
        # Execute 6 consecutive requests to trigger the 5-request limit
        for _ in range(6):
            res_rl = await runner.execute_scenario(rate_limit_scenario, target, test_client)
        assert res_rl.actual_status == 429
        assert res_rl.status == "passed"  # Security control is properly active!
