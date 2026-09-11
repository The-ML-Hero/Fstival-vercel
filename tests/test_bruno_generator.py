import os
import shutil
from pathlib import Path
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep, TargetConfig
from app.services.bruno.generator import BrunoCollectionGenerator


def test_bruno_collection_generation(tmp_path: Path):
    generator = BrunoCollectionGenerator(base_dir=str(tmp_path))
    target = TargetConfig(base_url="http://localhost:8080/api/v1", authorized=True)

    scenarios = [
        AttackScenario(
            scenario_id="SCENARIO-ATK-001",
            attack_id="ATK-001",
            category="BOLA",
            endpoint="/patients/{id}",
            method="GET",
            objective="BOLA access test",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="fetch_other_user_patient",
                    method="GET",
                    path="/patients/PATIENT-999",
                    headers={"Accept": "application/json"},
                    expected_status=403,
                )
            ],
            expected_secure_behavior="403 Forbidden",
            expected_status=403,
        ),
        AttackScenario(
            scenario_id="SCENARIO-ATK-002",
            attack_id="ATK-002",
            category="Input Validation",
            endpoint="/orders",
            method="POST",
            objective="Negative price test",
            steps=[
                AttackScenarioStep(
                    step_number=1,
                    step_name="submit_negative_price",
                    method="POST",
                    path="/orders",
                    body={"price": -50.0},
                    expected_status=400,
                )
            ],
            expected_secure_behavior="400 Bad Request",
            expected_status=400,
        )
    ]

    collection_dir = generator.generate_collection(
        project_id="test-proj-1",
        run_id="run-101",
        scenarios=scenarios,
        target=target
    )

    assert collection_dir.exists()
    assert (collection_dir / "bruno.json").exists()
    assert (collection_dir / "environments" / "local.bru").exists()

    # Verify category folders
    assert (collection_dir / "bola" / "ATK-001.bru").exists()
    assert (collection_dir / "input_validation" / "ATK-002.bru").exists()

    # Read .bru content
    with open(collection_dir / "bola" / "ATK-001.bru", "r", encoding="utf-8") as f:
        bru_text = f.read()

    assert "meta {" in bru_text
    assert "ATK-001" in bru_text
    assert "get {" in bru_text
    assert "{{baseUrl}}/patients/PATIENT-999" in bru_text
    assert "res.status: eq 403" in bru_text
