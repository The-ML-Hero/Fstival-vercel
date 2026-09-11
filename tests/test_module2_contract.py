from datetime import datetime, timezone
from app.schemas.module2_contract import (
    Module2AttackPlanExport,
    Module2ApiSummary,
    Module2Endpoint,
    Module2Parameter,
    Module2Role,
    Module2Resource,
    Module2Workflow,
    Module2AttackItem,
    Module2Mutation,
)


def test_module2_export_contract_validation():
    export_payload = Module2AttackPlanExport(
        contract_version="1.0.0",
        exported_at=datetime.now(timezone.utc),
        project_id="test-proj-uuid-1234",
        target_authorized=True,
        api_summary=Module2ApiSummary(
            title="ShopEasy API",
            version="1.0.0",
            openapi_version="3.0.1",
            description="Testing contract",
            target_base_url="http://localhost:8080",
            total_endpoints=1,
            total_resources=1,
            total_workflows=1,
            total_attacks_planned=1,
        ),
        endpoints=[
            Module2Endpoint(
                id="ep-1",
                method="GET",
                path="/patients/{id}",
                operation_id="getPatient",
                summary="Fetch patient",
                security_required=True,
                tags=["Patients"],
                security_schemes=[{"BearerAuth": []}],
                parameters=[
                    Module2Parameter(
                        name="id",
                        location="path",
                        type="string",
                        required=True,
                    )
                ],
                request_schemas=[],
                response_schemas=[{"type": "object"}],
            )
        ],
        roles=[
            Module2Role(
                role_name="doctor",
                confidence=0.91,
                reasoning="Clinical doctor scope",
                evidence=["Scope: doctor:clinical"],
                associated_endpoints=["GET /patients/{id}"],
            )
        ],
        resources=[
            Module2Resource(
                name="Patient",
                description="Patient entity",
                endpoints=["GET /patients/{id}"],
                crud_operations={"read": "GET /patients/{id}"},
                relationships=[],
            )
        ],
        workflows=[
            Module2Workflow(
                workflow_name="Patient Read Flow",
                confidence=0.88,
                steps=[],
                parameter_mappings=[],
            )
        ],
        attack_plan=[
            Module2AttackItem(
                attack_id="ATK-001",
                type="BOLA",
                endpoint="/patients/{id}",
                method="GET",
                objective="Access another user's patient file",
                preconditions=["Two user accounts exist"],
                steps=["1. Replace ID with target ID"],
                mutations=[
                    Module2Mutation(
                        parameter_name="id",
                        parameter_location="path",
                        mutation_type="cross_tenant_id",
                        payload_sample="00000000-0000-0000-0000-000000000002",
                        rationale="Test cross tenant access",
                    )
                ],
                expected_secure_behavior="403 Forbidden",
                reason="Object ID accepted in path without verification",
                severity="critical",
                exploitability=0.9,
                impact=0.95,
                confidence=0.92,
                priority_score=9.15,
                priority="critical",
            )
        ],
    )

    # Test serialization and deserialization
    json_data = export_payload.model_dump_json()
    assert "ATK-001" in json_data
    assert "BOLA" in json_data
    assert "cross_tenant_id" in json_data

    # Revalidate
    validated = Module2AttackPlanExport.model_validate_json(json_data)
    assert validated.project_id == "test-proj-uuid-1234"
    assert validated.attack_plan[0].priority == "critical"
