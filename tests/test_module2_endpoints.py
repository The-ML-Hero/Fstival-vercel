import os
import pytest
from httpx import AsyncClient

SAMPLE_HEALTHCARE_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "secure_healthcare_api.yaml")


@pytest.mark.asyncio
async def test_module2_runs_lifecycle(async_client: AsyncClient):
    # 1. Create Project & Import Spec & Analyze (Module 1 pipeline)
    proj_resp = await async_client.post("/api/v1/projects", json={
        "name": "Medicare Run Assessment",
        "target_authorized": True
    })
    assert proj_resp.status_code == 201
    project_id = proj_resp.json()["id"]

    with open(SAMPLE_HEALTHCARE_PATH, "r", encoding="utf-8") as f:
        spec_text = f.read()

    await async_client.post(
        f"/api/v1/projects/{project_id}/import/openapi",
        json={"spec_content": spec_text}
    )
    await async_client.post(f"/api/v1/projects/{project_id}/analyze")

    # 2. Create Test Run (Module 2)
    run_create_resp = await async_client.post(f"/api/v1/projects/{project_id}/runs", json={
        "target_authorized": True,
        "environment": "local"
    })
    assert run_create_resp.status_code == 201
    run_data = run_create_resp.json()
    run_id = run_data["id"]
    assert run_data["status"] == "pending"
    assert run_data["total_attacks"] > 0

    # 3. Get Test Run
    get_run_resp = await async_client.get(f"/api/v1/runs/{run_id}")
    assert get_run_resp.status_code == 200
    assert get_run_resp.json()["id"] == run_id

    # 4. Start Test Run
    start_resp = await async_client.post(f"/api/v1/runs/{run_id}/start")
    assert start_resp.status_code == 200
    completed_run = start_resp.json()
    assert completed_run["status"] in {"completed", "running"}

    # 5. Get Attacks List
    attacks_resp = await async_client.get(f"/api/v1/runs/{run_id}/attacks")
    assert attacks_resp.status_code == 200
    attacks_data = attacks_resp.json()
    assert attacks_data["total"] > 0
    assert len(attacks_data["attacks"]) > 0

    first_attack = attacks_data["attacks"][0]
    attack_id = first_attack["attack_id"]

    # 6. Get Single Attack Detail & Evidence
    single_atk_resp = await async_client.get(f"/api/v1/runs/{run_id}/attacks/{attack_id}")
    assert single_atk_resp.status_code == 200
    single_atk = single_atk_resp.json()
    assert single_atk["attack_id"] == attack_id
    assert len(single_atk["steps"]) > 0

    # 7. Replay Attack
    replay_resp = await async_client.post(f"/api/v1/runs/{run_id}/attacks/{attack_id}/replay")
    assert replay_resp.status_code == 200, f"Replay failed: {replay_resp.text}"
    replay_data = replay_resp.json()
    assert "status" in replay_data
    assert "diff_summary" in replay_data

    # 8. Raw Results Endpoint
    raw_resp = await async_client.get(f"/api/v1/runs/{run_id}/raw-results")
    assert raw_resp.status_code == 200
    raw_results = raw_resp.json()
    assert len(raw_results) > 0

    # 9. Export for Module 3
    mod3_resp = await async_client.get(f"/api/v1/runs/{run_id}/export/module3")
    assert mod3_resp.status_code == 200
    mod3_data = mod3_resp.json()
    assert mod3_data["contract_version"] == "1.0.0"
    assert mod3_data["run_id"] == run_id
    assert len(mod3_data["attack_results"]) > 0
