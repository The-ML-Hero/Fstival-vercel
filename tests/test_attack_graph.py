from app.db.models.vulnerability import VulnerabilityFinding
from app.services.analyzers.attack_graph_builder import AttackGraphBuilder


def test_attack_graph_nodes_and_edges_generation():
    builder = AttackGraphBuilder()

    findings = [
        VulnerabilityFinding(
            id="f-1",
            run_id="run-1",
            project_id="p-1",
            finding_id="VULN-001",
            attack_id="ATK-001",
            title="BOLA on /patients/{id}",
            type="BOLA / IDOR",
            endpoint="/patients/{id}",
            method="GET",
            severity="critical",
            confidence=0.95,
            status="confirmed",
            verification_status="unverified",
            risk_score=95,
            data_sensitivity="high",
            blast_radius_reach="All Tenant Resources",
            blast_radius_confidence=0.85,
            remediation_json={},
            evidence_json={},
            steps_json=[],
        ),
        VulnerabilityFinding(
            id="f-2",
            run_id="run-1",
            project_id="p-1",
            finding_id="VULN-002",
            attack_id="ATK-002",
            title="Broken Auth on /admin/users",
            type="Authentication Weakness",
            endpoint="/admin/users",
            method="GET",
            severity="critical",
            confidence=0.95,
            status="confirmed",
            verification_status="unverified",
            risk_score=95,
            data_sensitivity="high",
            blast_radius_reach="Global Internet",
            blast_radius_confidence=0.95,
            remediation_json={},
            evidence_json={},
            steps_json=[],
        ),
    ]

    graph, chains = builder.build_graph("run-1", findings)

    assert len(graph.nodes) > 4
    node_types = {n.type for n in graph.nodes}
    assert "role" in node_types
    assert "endpoint" in node_types
    assert "vulnerability" in node_types
    assert "impact" in node_types
    assert len(graph.edges) > 4

    # Verify compound chain was detected
    assert len(chains) > 0
    first_chain = chains[0]
    assert first_chain.overall_risk >= 90
    assert len(first_chain.nodes) > 0
    assert len(first_chain.edges) > 0
