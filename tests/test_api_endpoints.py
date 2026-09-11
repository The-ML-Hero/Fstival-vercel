import os
import pytest
from httpx import AsyncClient

SAMPLE_HEALTHCARE_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "secure_healthcare_api.yaml")
SAMPLE_ECOMMERCE_PATH = os.path.join(os.path.dirname(__file__), "..", "sample_specs", "vulnerable_ecommerce_api.yaml")


@pytest.mark.asyncio
async def test_full_api_workflow_healthcare(async_client: AsyncClient):
    # 1. Create Project
    create_resp = await async_client.post("/api/v1/projects", json={
        "name": "MediCare Clinic Assessment",
        "description": "Security audit for MediCare API",
        "target_authorized": True
    })
    assert create_resp.status_code == 201
    project_data = create_resp.json()
    project_id = project_data["id"]

    # 2. List Projects & Get Project
    list_resp = await async_client.get("/api/v1/projects")
    assert list_resp.status_code == 200
    assert len(list_resp.json()) >= 1

    get_resp = await async_client.get(f"/api/v1/projects/{project_id}")
    assert get_resp.status_code == 200
    assert get_resp.json()["name"] == "MediCare Clinic Assessment"

    # 3. Ingest OpenAPI spec via file upload
    with open(SAMPLE_HEALTHCARE_PATH, "rb") as f:
        import_resp = await async_client.post(
            f"/api/v1/projects/{project_id}/import/openapi",
            files={"file": ("secure_healthcare_api.yaml", f, "application/x-yaml")}
        )
    assert import_resp.status_code == 200
    import_data = import_resp.json()
    assert import_data["endpoints_count"] >= 5
    assert import_data["title"] == "MediCare Clinical Platform API"

    # 4. Discovery endpoints
    endpoints_resp = await async_client.get(f"/api/v1/projects/{project_id}/endpoints")
    assert endpoints_resp.status_code == 200
    endpoints = endpoints_resp.json()
    assert len(endpoints) >= 5

    # 5. Trigger Analysis
    analyze_resp = await async_client.post(f"/api/v1/projects/{project_id}/analyze")
    assert analyze_resp.status_code == 200, f"Analyze failed: {analyze_resp.text}"
    export_payload = analyze_resp.json()
    assert export_payload["contract_version"] == "1.0.0"
    assert len(export_payload["attack_plan"]) > 0

    # 6. Verify Discovery after Analysis (Resources, Workflows, Roles, Auth schemes)
    resources_resp = await async_client.get(f"/api/v1/projects/{project_id}/resources")
    assert resources_resp.status_code == 200
    assert len(resources_resp.json()) > 0

    workflows_resp = await async_client.get(f"/api/v1/projects/{project_id}/workflows")
    assert workflows_resp.status_code == 200
    assert len(workflows_resp.json()) > 0

    roles_resp = await async_client.get(f"/api/v1/projects/{project_id}/roles")
    assert roles_resp.status_code == 200
    assert len(roles_resp.json()) > 0

    auth_resp = await async_client.get(f"/api/v1/projects/{project_id}/auth-schemes")
    assert auth_resp.status_code == 200
    assert len(auth_resp.json()) > 0

    # 7. Fetch Attack Plan with filtering
    plan_resp = await async_client.get(f"/api/v1/projects/{project_id}/attack-plan")
    assert plan_resp.status_code == 200
    plan_data = plan_resp.json()
    assert plan_data["summary"]["total_attacks"] > 0
    assert len(plan_data["attack_plan"]) > 0

    # Filter by category
    bola_filter_resp = await async_client.get(f"/api/v1/projects/{project_id}/attack-plan?category=BOLA")
    assert bola_filter_resp.status_code == 200

    # Filter by priority
    crit_filter_resp = await async_client.get(f"/api/v1/projects/{project_id}/attack-plan?min_priority=critical")
    assert crit_filter_resp.status_code == 200

    # 8. Fetch Single Attack Hypothesis
    first_attack = plan_data["attack_plan"][0]
    atk_id = first_attack["attack_id"]
    single_resp = await async_client.get(f"/api/v1/projects/{project_id}/attack-plan/{atk_id}")
    assert single_resp.status_code == 200
    single_data = single_resp.json()
    assert single_data["attack_id"] == atk_id
    assert "objective" in single_data

    # 9. Module 2 Export Endpoint
    module2_resp = await async_client.get(f"/api/v1/projects/{project_id}/export/module2")
    assert module2_resp.status_code == 200
    mod2_data = module2_resp.json()
    assert mod2_data["project_id"] == project_id
    assert "api_summary" in mod2_data
    assert "attack_plan" in mod2_data

    # 10. Update & Delete Project
    patch_resp = await async_client.patch(f"/api/v1/projects/{project_id}", json={"description": "Updated description"})
    assert patch_resp.status_code == 200
    assert patch_resp.json()["description"] == "Updated description"

    del_resp = await async_client.delete(f"/api/v1/projects/{project_id}")
    assert del_resp.status_code == 204


@pytest.mark.asyncio
async def test_vulnerable_ecommerce_spec_analysis(async_client: AsyncClient):
    # 1. Create Project
    create_resp = await async_client.post("/api/v1/projects", json={
        "name": "ShopEasy Vulnerable Demo",
        "target_authorized": True
    })
    project_id = create_resp.json()["id"]

    # 2. Ingest Vulnerable Spec via raw string in json body
    with open(SAMPLE_ECOMMERCE_PATH, "r", encoding="utf-8") as f:
        spec_text = f.read()

    import_resp = await async_client.post(
        f"/api/v1/projects/{project_id}/import/openapi",
        json={"spec_content": spec_text}
    )
    assert import_resp.status_code == 200

    # 3. Analyze
    analyze_resp = await async_client.post(f"/api/v1/projects/{project_id}/analyze")
    assert analyze_resp.status_code == 200
    analysis = analyze_resp.json()

    # Check for BOLA on /orders/{orderId}
    bola_attacks = [a for a in analysis["attack_plan"] if a["type"] == "BOLA"]
    assert len(bola_attacks) > 0

    # Check for Business logic on refund
    bl_attacks = [a for a in analysis["attack_plan"] if a["type"] == "Business Logic"]
    assert len(bl_attacks) > 0


@pytest.mark.asyncio
async def test_error_handling_nonexistent_project(async_client: AsyncClient):
    # Nonexistent project 404s
    resp = await async_client.get("/api/v1/projects/non-existent-uuid-99999")
    assert resp.status_code == 404

    analyze_resp = await async_client.post("/api/v1/projects/non-existent-uuid-99999/analyze")
    assert analyze_resp.status_code == 404

    export_resp = await async_client.get("/api/v1/projects/non-existent-uuid-99999/export/module2")
    assert export_resp.status_code == 404


@pytest.mark.asyncio
async def test_health_check_endpoint(async_client: AsyncClient):
    resp = await async_client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "healthy"
