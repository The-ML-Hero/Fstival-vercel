import os
import pytest
from httpx import AsyncClient

SAMPLE_HEALTHCARE_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "secure_healthcare_api.yaml")


@pytest.mark.asyncio
async def test_module3_api_endpoints_workflow(async_client: AsyncClient):
    # 1. Ingest & Analyze via Module 1
    proj_resp = await async_client.post("/api/v1/projects", json={
        "name": "Module 3 Assessment Proj",
        "target_authorized": True
    })
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    with open(SAMPLE_HEALTHCARE_PATH, "r", encoding="utf-8") as f:
        spec_text = f.read()

    await async_client.post(f"/api/v1/projects/{project_id}/import/openapi", json={"spec_content": spec_text})
    await async_client.post(f"/api/v1/projects/{project_id}/analyze")

    # 2. Execute Test Run via Module 2
    run_resp = await async_client.post(f"/api/v1/projects/{project_id}/runs", json={"target_authorized": True})
    assert run_resp.status_code == 201
    run_id = run_resp.json()["id"]
    await async_client.post(f"/api/v1/runs/{run_id}/start")

    # 3. Test Findings Endpoint (Module 3)
    findings_resp = await async_client.get(f"/api/v1/runs/{run_id}/findings")
    assert findings_resp.status_code == 200
    findings_data = findings_resp.json()
    assert "total" in findings_data
    assert "findings" in findings_data

    if findings_data["total"] > 0:
        first_f = findings_data["findings"][0]
        finding_id = first_f["finding_id"]

        # Detail endpoint
        detail_resp = await async_client.get(f"/api/v1/runs/{run_id}/findings/{finding_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["finding_id"] == finding_id
        assert detail["remediation"] is not None
        assert "what_to_change" in detail["remediation"]

    # 4. Test Security Score Endpoint
    score_resp = await async_client.get(f"/api/v1/runs/{run_id}/score")
    assert score_resp.status_code == 200
    score_data = score_resp.json()
    assert 0 <= score_data["security_score"] <= 100
    assert "risk_level" in score_data

    # 5. Test Attack Graph Endpoint
    graph_resp = await async_client.get(f"/api/v1/runs/{run_id}/attack-graph")
    assert graph_resp.status_code == 200
    graph_data = graph_resp.json()
    assert "nodes" in graph_data
    assert "edges" in graph_data

    # 6. Test Attack Chains Endpoint
    chains_resp = await async_client.get(f"/api/v1/runs/{run_id}/attack-chains")
    assert chains_resp.status_code == 200
    chains_data = chains_resp.json()
    assert "chains" in chains_data

    # 7. Test Executive Report Endpoint
    report_resp = await async_client.get(f"/api/v1/runs/{run_id}/report")
    assert report_resp.status_code == 200, f"Report failed: {report_resp.text}"
    report_data = report_resp.json()
    assert "executive_summary" in report_data
    assert "remediation_roadmap" in report_data
    assert "ci_gate" in report_data

    # 8. Test CI/CD Security Gate Endpoint
    gate_resp = await async_client.post(
        f"/api/v1/runs/{run_id}/security-gate",
        json={"fail_on_critical": True, "min_security_score": 50}
    )
    assert gate_resp.status_code == 200
    gate_data = gate_resp.json()
    assert gate_data["status"] in {"passed", "failed"}
    assert gate_data["exit_code"] in {0, 1}

    # 9. Test History Endpoint
    hist_resp = await async_client.get(f"/api/v1/projects/{project_id}/history")
    assert hist_resp.status_code == 200
    hist_data = hist_resp.json()
    assert hist_data["total_scans"] >= 1

    # 10. Test Regressions Endpoint
    reg_resp = await async_client.get(f"/api/v1/projects/{project_id}/regressions")
    assert reg_resp.status_code == 200
    reg_data = reg_resp.json()
    assert "regressions" in reg_data
    assert "score_delta" in reg_data
