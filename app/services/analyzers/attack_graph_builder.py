from typing import Any, Dict, List, Tuple
from app.db.models.vulnerability import VulnerabilityFinding
from app.schemas.module3.graph import (
    GraphNode,
    GraphEdge,
    AttackGraphResponse,
    AttackChainResponse,
)


class AttackGraphBuilder:
    """
    Builds topological attack graphs and discovers multi-stage compound attack chains.
    """

    def build_graph(
        self,
        run_id: str,
        findings: List[VulnerabilityFinding]
    ) -> Tuple[AttackGraphResponse, List[AttackChainResponse]]:
        """
        Constructs full attack graph nodes & edges and extracts compound attack chains.
        """
        nodes_dict: Dict[str, GraphNode] = {}
        edges: List[GraphEdge] = []

        # Always add root Actor/Role nodes
        roles = ["role:anonymous", "role:user", "role:staff", "role:admin"]
        for r in roles:
            r_name = r.split(":")[1]
            nodes_dict[r] = GraphNode(id=r, label=f"Role: {r_name.capitalize()}", type="role", metadata={"role": r_name})

        # Add Nodes for each finding
        for f in findings:
            ep_id = f"endpoint:{f.method}:{f.endpoint}"
            vuln_id = f"vuln:{f.finding_id}"
            impact_id = f"impact:{f.finding_id}"

            # Endpoint Node
            if ep_id not in nodes_dict:
                nodes_dict[ep_id] = GraphNode(
                    id=ep_id,
                    label=f"{f.method} {f.endpoint}",
                    type="endpoint",
                    metadata={"method": f.method, "endpoint": f.endpoint}
                )

            # Vulnerability Node
            nodes_dict[vuln_id] = GraphNode(
                id=vuln_id,
                label=f"{f.type} ({f.severity.upper()})",
                type="vulnerability",
                metadata={"severity": f.severity, "risk_score": f.risk_score, "finding_id": f.finding_id}
            )

            # Impact Node
            nodes_dict[impact_id] = GraphNode(
                id=impact_id,
                label=f"Impact: {f.confirmed_impact or f.type}",
                type="impact",
                metadata={"reach": f.blast_radius_reach}
            )

            # Connect Role -> Endpoint
            actor_role = "role:anonymous" if "authentication" in f.type.lower() else "role:user"
            edges.append(GraphEdge(source=actor_role, target=ep_id, relation="accesses", label="Initiates Request"))

            # Connect Endpoint -> Vulnerability
            edges.append(GraphEdge(source=ep_id, target=vuln_id, relation="exploits", label="Exposes Flaw"))

            # Connect Vulnerability -> Impact
            edges.append(GraphEdge(source=vuln_id, target=impact_id, relation="results_in", label="Causes Damage"))

        # Build compound attack chains
        chains = self._detect_attack_chains(run_id, findings, nodes_dict)

        graph_response = AttackGraphResponse(
            run_id=run_id,
            nodes=list(nodes_dict.values()),
            edges=edges,
        )

        return graph_response, chains

    def _detect_attack_chains(
        self,
        run_id: str,
        findings: List[VulnerabilityFinding],
        all_nodes: Dict[str, GraphNode]
    ) -> List[AttackChainResponse]:
        """
        Analyzes findings to identify multi-stage compound attack paths.
        """
        chains: List[AttackChainResponse] = []
        types = {f.type.lower(): f for f in findings}

        chain_counter = 1

        # Chain 1: Broken Auth / Exposure -> BOLA Data Exfiltration Chain
        auth_f = next((f for f in findings if "authentication" in f.type.lower() or "exposure" in f.type.lower()), None)
        bola_f = next((f for f in findings if "bola" in f.type.lower() or "authorization" in f.type.lower()), None)

        if auth_f and bola_f:
            chain_nodes = [
                GraphNode(id="role:anonymous", label="Anonymous Attacker", type="role"),
                GraphNode(id=f"ep:{auth_f.endpoint}", label=f"{auth_f.method} {auth_f.endpoint}", type="endpoint"),
                GraphNode(id=f"vuln:{auth_f.finding_id}", label="Unauthenticated Resource Discovery", type="vulnerability"),
                GraphNode(id=f"ep:{bola_f.endpoint}", label=f"{bola_f.method} {bola_f.endpoint}", type="endpoint"),
                GraphNode(id=f"vuln:{bola_f.finding_id}", label="BOLA Cross-Tenant Data Access", type="vulnerability"),
                GraphNode(id="impact:data_leak", label="Mass Customer Data Exfiltration", type="impact"),
            ]
            chain_edges = [
                GraphEdge(source="role:anonymous", target=f"ep:{auth_f.endpoint}", relation="accesses"),
                GraphEdge(source=f"ep:{auth_f.endpoint}", target=f"vuln:{auth_f.finding_id}", relation="exploits"),
                GraphEdge(source=f"vuln:{auth_f.finding_id}", target=f"ep:{bola_f.endpoint}", relation="escalates_to", label="Uses Harvested IDs"),
                GraphEdge(source=f"ep:{bola_f.endpoint}", target=f"vuln:{bola_f.finding_id}", relation="exploits"),
                GraphEdge(source=f"vuln:{bola_f.finding_id}", target="impact:data_leak", relation="results_in"),
            ]
            chains.append(AttackChainResponse(
                chain_id=f"CHAIN-{chain_counter:03d}",
                title="Unauthenticated Enumeration to Cross-Tenant BOLA Exfiltration",
                overall_risk=95,
                explanation=(
                    "An unauthenticated attacker discovers predictable resource identifiers on public endpoints, "
                    "then leverages BOLA on protected resources to harvest records across tenant boundaries."
                ),
                nodes=chain_nodes,
                edges=chain_edges,
            ))
            chain_counter += 1

        # Chain 2: Role Escalation -> Admin Takeover Chain
        role_f = next((f for f in findings if "role escalation" in f.type.lower()), None)
        if role_f:
            chain_nodes = [
                GraphNode(id="role:user", label="Authenticated User", type="role"),
                GraphNode(id=f"ep:{role_f.endpoint}", label=f"{role_f.method} {role_f.endpoint}", type="endpoint"),
                GraphNode(id=f"vuln:{role_f.finding_id}", label="Mass Assignment Role Override", type="vulnerability"),
                GraphNode(id="role:admin", label="Elevated Admin Account", type="role"),
                GraphNode(id="impact:admin_takeover", label="Full System Administration Takeover", type="impact"),
            ]
            chain_edges = [
                GraphEdge(source="role:user", target=f"ep:{role_f.endpoint}", relation="accesses"),
                GraphEdge(source=f"ep:{role_f.endpoint}", target=f"vuln:{role_f.finding_id}", relation="exploits"),
                GraphEdge(source=f"vuln:{role_f.finding_id}", target="role:admin", relation="escalates_to"),
                GraphEdge(source="role:admin", target="impact:admin_takeover", relation="results_in"),
            ]
            chains.append(AttackChainResponse(
                chain_id=f"CHAIN-{chain_counter:03d}",
                title="Privilege Escalation to Administrative System Compromise",
                overall_risk=98,
                explanation=(
                    "A standard user modifies account metadata via mass assignment to gain admin rights, "
                    "bypassing authorization controls to achieve total administrative control."
                ),
                nodes=chain_nodes,
                edges=chain_edges,
            ))
            chain_counter += 1

        # Chain 3: Financial Tampering & Workflow Violation Chain
        tamper_f = next((f for f in findings if "input validation" in f.type.lower() or "tampering" in f.type.lower()), None)
        wf_f = next((f for f in findings if "workflow" in f.type.lower() or "business logic" in f.type.lower()), None)

        if tamper_f or wf_f:
            target_f = tamper_f or wf_f
            chain_nodes = [
                GraphNode(id="role:user", label="Authenticated User", type="role"),
                GraphNode(id=f"ep:{target_f.endpoint}", label=f"{target_f.method} {target_f.endpoint}", type="endpoint"),
                GraphNode(id=f"vuln:{target_f.finding_id}", label="Financial Parameter & Workflow Flaw", type="vulnerability"),
                GraphNode(id="impact:financial_fraud", label="Direct Financial Loss & Ledger Distortion", type="impact"),
            ]
            chain_edges = [
                GraphEdge(source="role:user", target=f"ep:{target_f.endpoint}", relation="accesses"),
                GraphEdge(source=f"ep:{target_f.endpoint}", target=f"vuln:{target_f.finding_id}", relation="exploits"),
                GraphEdge(source=f"vuln:{target_f.finding_id}", target="impact:financial_fraud", relation="results_in"),
            ]
            chains.append(AttackChainResponse(
                chain_id=f"CHAIN-{chain_counter:03d}",
                title="Business Logic & State Manipulation Financial Fraud Chain",
                overall_risk=90,
                explanation=(
                    "An attacker manipulates payment amounts or triggers out-of-order state transitions (such as refunds "
                    "before payments) causing financial imbalance."
                ),
                nodes=chain_nodes,
                edges=chain_edges,
            ))

        return chains
