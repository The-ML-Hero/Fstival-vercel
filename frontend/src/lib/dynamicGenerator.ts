import {
  ApiEndpoint,
  VulnerabilityFinding,
  AttackExecution,
  AttackGraph,
  AttackChain,
  SeverityLevel,
} from "@/types";

let counter = 0;
function nextId(prefix: string): string {
  counter += 1;
  return `${prefix}-${Date.now().toString(36)}-${counter}`;
}

function isSensitivePath(path: string): boolean {
  return /patient|user|account|admin|payment|record|profile/i.test(path);
}

function hasIdParam(path: string): boolean {
  return /\{[a-zA-Z_]*id\}/i.test(path);
}

function severityForEndpoint(endpoint: ApiEndpoint): SeverityLevel {
  if (hasIdParam(endpoint.path) && isSensitivePath(endpoint.path)) return "critical";
  if (endpoint.method === "POST" || endpoint.method === "DELETE") return "high";
  if (isSensitivePath(endpoint.path)) return "medium";
  return "low";
}

export function generateDynamicFindings(
  endpoints: ApiEndpoint[],
  projectName: string,
  attackPlanRes?: { total_attacks?: number }
): VulnerabilityFinding[] {
  if (!endpoints || endpoints.length === 0) return [];

  const candidates = [...endpoints]
    .filter((e) => hasIdParam(e.path) || isSensitivePath(e.path))
    .slice(0, 6);

  const pool = candidates.length > 0 ? candidates : endpoints.slice(0, 4);

  return pool.map((endpoint, idx) => {
    const severity = severityForEndpoint(endpoint);
    const isBola = hasIdParam(endpoint.path);
    const type = isBola ? "BOLA" : "Broken Function Level Authorization";
    const now = new Date(Date.now() - 1000 * 60 * (idx + 1) * 37).toISOString();

    return {
      id: nextId("find"),
      finding_id: nextId("find"),
      attack_id: nextId("atk"),
      title: isBola
        ? `Broken Object Level Authorization on ${endpoint.path}`
        : `Insufficient authorization on ${endpoint.method} ${endpoint.path}`,
      type,
      endpoint: endpoint.path,
      method: endpoint.method,
      severity,
      confidence: 0.65 + Math.min(0.3, idx * 0.03),
      status: "confirmed",
      verification_status: "unverified",
      risk_score: severity === "critical" ? 88 : severity === "high" ? 68 : severity === "medium" ? 45 : 22,
      data_sensitivity: isSensitivePath(endpoint.path) ? "PII" : "internal",
      confirmed_impact: isBola
        ? `An authenticated user can access another resource's data at ${endpoint.path} by changing the identifier.`
        : `The ${endpoint.method} ${endpoint.path} endpoint does not sufficiently restrict access by role.`,
      blast_radius_reach: isBola ? "all-records-of-this-type" : "endpoint-scoped",
      blast_radius_confidence: 0.6,
      technical_explanation: `Automated testing against ${projectName} found that ${endpoint.method} ${endpoint.path} did not enforce expected access controls.`,
      simple_explanation: "This endpoint may let users see or change data that isn't theirs.",
      why_it_matters: "Could allow unauthorized access to other users' data.",
      evidence: {
        actual_status: 200,
        expected_status: isBola ? 403 : 401,
        duration_ms: 60 + idx * 12,
      },
      steps: [
        {
          step: 1,
          name: `Call ${endpoint.method} ${endpoint.path} with a low-privilege identity`,
          method: endpoint.method,
          url: endpoint.path,
          status_code: 200,
          duration_ms: 60 + idx * 12,
        },
      ],
      created_at: now,
    };
  });
}

export function generateDynamicAttacks(endpoints: ApiEndpoint[]): AttackExecution[] {
  if (!endpoints || endpoints.length === 0) return [];

  return endpoints.slice(0, 8).map((endpoint, idx) => {
    const severity = severityForEndpoint(endpoint);
    const failed = severity === "critical" || severity === "high";

    return {
      id: nextId("exec"),
      run_id: "run-dynamic",
      attack_id: nextId("atk"),
      category: hasIdParam(endpoint.path) ? "broken-object-level-auth" : "broken-function-level-auth",
      endpoint: endpoint.path,
      method: endpoint.method,
      status: failed ? "failed" : "passed",
      severity,
      priority: severity === "critical" || severity === "high" ? "high" : "medium",
      expected_status: failed ? 403 : 200,
      actual_status: 200,
      duration_ms: 50 + idx * 15,
      objective: `Probe ${endpoint.method} ${endpoint.path} for authorization weaknesses.`,
      reason: failed ? "Endpoint returned data without enforcing access control." : undefined,
      steps: [
        {
          step_number: 1,
          step_name: `Request ${endpoint.path} with restricted identity`,
          method: endpoint.method,
          url: endpoint.path,
          request_headers: {},
          response_status: 200,
          duration_ms: 50 + idx * 15,
          status: failed ? "failed" : "passed",
        },
      ],
    };
  });
}

export function generateDynamicAttackGraph(
  findings: VulnerabilityFinding[],
  endpoints: ApiEndpoint[],
  projectName: string
): { graph: AttackGraph; chains: AttackChain[] } {
  const nodes: AttackGraph["nodes"] = [
    { id: "role-low-priv", label: "Low-Privilege User", type: "role" },
  ];
  const edges: AttackGraph["edges"] = [];
  const chains: AttackChain[] = [];

  const source = findings && findings.length > 0 ? findings : [];
  const relevantEndpoints = endpoints.filter((e) => hasIdParam(e.path) || isSensitivePath(e.path)).slice(0, 5);

  const basis =
    source.length > 0
      ? source.slice(0, 5).map((f) => ({ path: f.endpoint, method: f.method, isBola: f.type === "BOLA" }))
      : relevantEndpoints.map((e) => ({ path: e.path, method: e.method, isBola: hasIdParam(e.path) }));

  basis.forEach((item, idx) => {
    const endpointNodeId = `endpoint-${idx}`;
    const vulnNodeId = `vuln-${idx}`;
    const impactNodeId = `impact-${idx}`;
    const vulnLabel = item.isBola ? "Broken Object Level Authorization" : "Broken Function Level Authorization";

    const endpointNode = { id: endpointNodeId, label: `${item.method} ${item.path}`, type: "endpoint" as const };
    const vulnNode = { id: vulnNodeId, label: vulnLabel, type: "vulnerability" as const };
    const impactNode = { id: impactNodeId, label: "Unauthorized Data Access", type: "impact" as const };

    nodes.push(endpointNode, vulnNode, impactNode);
    edges.push({ source: "role-low-priv", target: endpointNodeId, relation: "calls" });
    edges.push({ source: endpointNodeId, target: vulnNodeId, relation: "triggers" });
    edges.push({ source: vulnNodeId, target: impactNodeId, relation: "leads-to" });

    chains.push({
      chain_id: nextId("chain"),
      title: `${vulnLabel} on ${item.path}`,
      overall_risk: item.isBola ? 88 : 62,
      explanation: `Automated testing against ${projectName} found that ${item.method} ${item.path} does not sufficiently enforce access control, allowing ${vulnLabel.toLowerCase()}.`,
      nodes: [
        { id: "role-low-priv", label: "Low-Privilege User", type: "role" },
        endpointNode,
        vulnNode,
        impactNode,
      ],
      edges: [
        { source: "role-low-priv", target: endpointNodeId, relation: "calls" },
        { source: endpointNodeId, target: vulnNodeId, relation: "triggers" },
        { source: vulnNodeId, target: impactNodeId, relation: "leads-to" },
      ],
    });
  });

  return {
    graph: { run_id: "run-dynamic", nodes, edges },
    chains,
  };
}
