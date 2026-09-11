import os
import pytest
from httpx import AsyncClient

SAMPLE_HEALTHCARE_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "secure_healthcare_api.yaml")


@pytest.mark.asyncio
async def test_full_system_e2e_integration_pipeline(async_client: AsyncClient):
    """
    Complete end-to-end pipeline test across:
    Module 1 (API Discovery & Attack Plan) ->
    Module 2 (Bruno Execution & Simulation) ->
    Module 3 (Security Findings, Risk Score, Attack Graph, Fix Verification, Regressions & CI Gate)
    """

    # 1. Health Checks
    health_resp = await async_client.get("/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["status"] == "healthy"

    dep_resp = await async_client.get("/health/dependencies")
    assert dep_resp.status_code == 200
    assert "dependencies" in dep_resp.json()

    # 2. STEP 1 & 2: Create Project
    proj_resp = await async_client.post("/api/v1/projects", json={
        "name": "E2E Clinical Security Project",
        "description": "Full-system integration verification against local target",
        "target_base_url": "http://testserver/demo",
        "target_authorized": True,
    })
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    # 3. STEP 3 & 4: Import OpenAPI Specification
    with open(SAMPLE_HEALTHCARE_PATH, "r", encoding="utf-8") as f:
        spec_content = f.read()

    import_resp = await async_client.post(
        f"/api/v1/projects/{project_id}/import/openapi",
        json={"spec_content": spec_content}
    )
    assert import_resp.status_code == 200
    assert import_resp.json()["endpoints_count"] > 0

    # 4. STEP 5 & 6: Trigger Module 1 API Intelligence Analysis & Verify Discovery
    analyze_resp = await async_client.post(f"/api/v1/projects/{project_id}/analyze")
    assert analyze_resp.status_code == 200

    ep_resp = await async_client.get(f"/api/v1/projects/{project_id}/endpoints")
    assert ep_resp.status_code == 200
    assert len(ep_resp.json()) > 0

    # 5. STEP 7 & 8: Verify Module 1 Attack Plan Generation
    plan_resp = await async_client.get(f"/api/v1/projects/{project_id}/attack-plan")
    assert plan_resp.status_code == 200
    assert len(plan_resp.json()["attack_plan"]) > 0

    # 6. STEP 9, 10, 11: Initialize Module 2 Test Run & Execute Attacks
    run_create_resp = await async_client.post(
        f"/api/v1/projects/{project_id}/runs",
        json={"target_base_url": "http://testserver/demo", "target_authorized": True, "environment": "local"}
    )
    assert run_create_resp.status_code == 201
    run_id = run_create_resp.json()["id"]

    run_start_resp = await async_client.post(f"/api/v1/runs/{run_id}/start")
    assert run_start_resp.status_code == 200
    assert run_start_resp.json()["status"] == "completed"

    # 7. STEP 12 & 13: Verify Executions & Evidence Collection (Module 2)
    attacks_resp = await async_client.get(f"/api/v1/runs/{run_id}/attacks")
    assert attacks_resp.status_code == 200
    attacks = attacks_resp.json()["attacks"]
    assert len(attacks) > 0

    first_attack_id = attacks[0]["attack_id"]

    # 8. STEP 14, 15, 16: Verify Module 3 Findings & Risk Score
    findings_resp = await async_client.get(f"/api/v1/runs/{run_id}/findings")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert "findings" in findings_data
    assert findings_data["total"] >= 1

    first_finding = findings_data["findings"][0]
    finding_db_id = first_finding["id"]
    finding_code_id = first_finding["finding_id"]

    # Finding Detail
    detail_resp = await async_client.get(f"/api/v1/runs/{run_id}/findings/{finding_code_id}")
    assert detail_resp.status_code == 200
    detail = detail_resp.json()
    assert detail["remediation"] is not None

    # Security Score
    score_resp = await async_client.get(f"/api/v1/runs/{run_id}/score")
    assert score_resp.status_code == 200
    assert 0 <= score_resp.json()["security_score"] <= 100

    # 9. STEP 17: Verify Attack Graph & Compound Chains
    graph_resp = await async_client.get(f"/api/v1/runs/{run_id}/attack-graph")
    assert graph_resp.status_code == 200
    assert len(graph_resp.json()["nodes"]) > 0

    chains_resp = await async_client.get(f"/api/v1/runs/{run_id}/attack-chains")
    assert chains_resp.status_code == 200
    assert "chains" in chains_resp.json()

    # 10. STEP 18 & 19: Replay Attack
    replay_resp = await async_client.post(f"/api/v1/runs/{run_id}/attacks/{first_attack_id}/replay")
    assert replay_resp.status_code == 200
    assert replay_resp.json()["status"] in {"reproduced", "changed"}

    # 11. STEP 20, 21, 22, 23, 24: Fix Verification
    verify_resp = await async_client.post(f"/api/v1/findings/{finding_db_id}/verify-fix")
    assert verify_resp.status_code == 200
    assert "result" in verify_resp.json()

    # 12. STEP 25 & 26: History & CI/CD Security Gate
    hist_resp = await async_client.get(f"/api/v1/projects/{project_id}/history")
    assert hist_resp.status_code == 200
    assert hist_resp.json()["total_scans"] >= 1

    gate_resp = await async_client.post(
        f"/api/v1/runs/{run_id}/security-gate",
        json={"fail_on_critical": True, "min_security_score": 60}
    )
    assert gate_resp.status_code == 200
    assert gate_resp.json()["status"] in {"passed", "failed"}
