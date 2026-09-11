import pytest
from app.services.ai.fallback_adapter import FallbackAIProvider
from app.schemas.workflow import WorkflowResponse, WorkflowStep, ParameterMapping


@pytest.mark.asyncio
async def test_all_10_attack_categories_generated():
    provider = FallbackAIProvider()

    context = {
        "endpoints": [
            {
                "method": "POST",
                "path": "/auth/login",
                "security_required": False,
                "parameters": [],
                "schemas": []
            },
            {
                "method": "GET",
                "path": "/patients/{id}",
                "security_required": True,
                "parameters": [
                    {"name": "id", "location": "path", "param_type": "string"},
                    {"name": "age", "location": "query", "param_type": "integer"}
                ],
                "schemas": []
            },
            {
                "method": "POST",
                "path": "/admin/config",
                "security_required": True,
                "parameters": [
                    {"name": "amount", "location": "body", "param_type": "number"}
                ],
                "schemas": []
            }
        ],
        "roles": [
            {"role_name": "admin", "confidence": 0.9, "reasoning": "Admin", "evidence": [], "associated_endpoints": []}
        ],
        "resources": [],
        "workflows": [
            WorkflowResponse(
                workflow_name="Payment Refund Flow",
                description="Refund workflow",
                confidence=0.9,
                steps=[
                    WorkflowStep(step_number=1, step_name="pay_order", endpoint="/pay", method="POST"),
                    WorkflowStep(step_number=2, step_name="refund_order", endpoint="/refund", method="POST")
                ],
                parameter_mappings=[]
            )
        ]
    }

    res = await provider.analyze_api(context)
    categories = {h.category for h in res.attack_hypotheses}

    expected_categories = {
        "Authentication",
        "Authorization",
        "BOLA",
        "Role Escalation",
        "Input Validation",
        "Parameter Tampering",
        "Rate-Limit Testing",
        "HTTP Method Abuse",
        "Information Exposure",
        "Business Logic",
    }

    assert expected_categories.issubset(categories)
    assert len(res.attack_hypotheses) >= 10
    for h in res.attack_hypotheses:
        assert h.attack_id.startswith("ATK-")
        assert len(h.objective) > 0
        assert len(h.expected_secure_behavior) > 0
