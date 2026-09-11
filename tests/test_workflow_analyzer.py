from app.schemas.resource import ResourceEntityResponse
from app.services.analyzers.workflow_analyzer import WorkflowAnalyzer


def test_workflow_discovery_and_parameter_chaining():
    endpoints = [
        {
            "method": "POST",
            "path": "/auth/login",
            "security_required": False
        },
        {
            "method": "GET",
            "path": "/users/me",
            "security_required": True
        },
        {
            "method": "POST",
            "path": "/orders",
            "security_required": True
        },
        {
            "method": "POST",
            "path": "/orders/{orderId}/pay",
            "security_required": True
        },
        {
            "method": "POST",
            "path": "/orders/{orderId}/refund",
            "security_required": True
        }
    ]

    resources = [
        ResourceEntityResponse(
            name="Order",
            description="Order domain resource",
            endpoints=["POST /orders", "POST /orders/{orderId}/pay", "POST /orders/{orderId}/refund"],
            crud_operations={"create": "POST /orders"},
            relationships=[]
        )
    ]

    analyzer = WorkflowAnalyzer()
    res = analyzer.analyze(endpoints, resources)

    assert res.total_workflows >= 2
    wf_names = [w.workflow_name for w in res.workflows]

    assert any("Authentication" in name for name in wf_names)
    assert any("Order Settlement" in name for name in wf_names)

    settlement_wf = next(w for w in res.workflows if "Order Settlement" in w.workflow_name)
    assert len(settlement_wf.steps) >= 3
    assert len(settlement_wf.parameter_mappings) >= 1
