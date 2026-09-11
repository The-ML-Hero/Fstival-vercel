export type ViewMode =
  | "dashboard"
  | "api-overview"
  | "api-import"
  | "attack-center"
  | "live-simulation"
  | "vulnerabilities"
  | "attack-graph"
  | "ai-analyst"
  | "fix-center"
  | "history"
  | "settings";

export type SeverityLevel = "critical" | "high" | "medium" | "low";
export type FindingStatus = "confirmed" | "likely" | "inconclusive" | "false-positive" | "resolved";
export type VerificationResult = "unverified" | "fixed" | "not_fixed" | "regression" | "inconclusive";

export interface Project {
  id: string;
  name: string;
  description?: string;
  target_base_url?: string;
  target_authorized: boolean;
  created_at: string;
  updated_at: string;
}

export interface ApiEndpoint {
  id: string;
  path: string;
  method: string;
  summary?: string;
  operation_id?: string;
  tags: string[];
  is_authenticated: boolean;
}

export interface ApiResource {
  name: string;
  endpoints_count: number;
  related_resources: string[];
  description?: string;
}

export interface ApiWorkflow {
  id: string;
  name: string;
  steps: {
    step_number: number;
    operation: string;
    endpoint: string;
    method: string;
  }[];
}

export interface AttackCategorySummary {
  category: string;
  name: string;
  icon: string;
  description: string;
  attack_count: number;
  potential_issues: number;
  severity: SeverityLevel;
}

export interface TestRun {
  id: string;
  project_id: string;
  target_base_url: string;
  target_authorized: boolean;
  environment: string;
  status: "pending" | "running" | "completed" | "failed" | "stopped";
  total_attacks: number;
  passed_attacks: number;
  failed_attacks: number;
  error_attacks: number;
  started_at?: string;
  completed_at?: string;
}

export interface AttackStepExecution {
  step_number: number;
  step_name: string;
  method: string;
  url: string;
  request_headers: Record<string, string>;
  request_body?: string;
  response_status?: number;
  response_body?: string;
  duration_ms: number;
  status: "passed" | "failed" | "error";
  error_message?: string;
}

export interface AttackExecution {
  id: string;
  run_id: string;
  attack_id: string;
  category: string;
  endpoint: string;
  method: string;
  status: "passed" | "failed" | "error" | "running" | "pending";
  severity: SeverityLevel;
  priority: string;
  expected_status?: number;
  actual_status?: number;
  duration_ms: number;
  objective?: string;
  reason?: string;
  is_adaptive?: boolean;
  parent_attack_id?: string;
  steps: AttackStepExecution[];
}

export interface RemediationRecommendation {
  what_to_change: string;
  why: string;
  secure_design_principle: string;
  example_pseudocode: string;
  target_framework: string;
}

export interface VulnerabilityFinding {
  id: string;
  finding_id: string;
  attack_id: string;
  title: string;
  type: string;
  endpoint: string;
  method: string;
  severity: SeverityLevel;
  confidence: number;
  status: FindingStatus;
  verification_status: VerificationResult;
  risk_score: number;
  data_sensitivity: string;
  confirmed_impact?: string;
  potential_impact?: string;
  blast_radius_reach: string;
  blast_radius_confidence: number;
  blast_radius_reasoning?: string;
  technical_explanation?: string;
  simple_explanation?: string;
  evidence_explanation?: string;
  why_it_matters?: string;
  remediation?: RemediationRecommendation;
  evidence: {
    request_headers?: Record<string, string>;
    response_headers?: Record<string, string>;
    response_body?: string;
    duration_ms?: number;
    actual_status?: number;
    expected_status?: number;
  };
  steps: {
    step: number;
    name: string;
    method: string;
    url: string;
    status_code?: number;
    duration_ms?: number;
  }[];
  created_at: string;
}

export interface SecurityScore {
  security_score: number;
  risk_level: "low" | "medium" | "high" | "critical";
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  score_calculation_details?: Record<string, number>;
}

export interface GraphNode {
  id: string;
  label: string;
  type: "role" | "endpoint" | "vulnerability" | "resource" | "impact" | "step";
  metadata?: Record<string, any>;
}

export interface GraphEdge {
  source: string;
  target: string;
  relation: string;
  label?: string;
}

export interface AttackGraph {
  run_id: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface AttackChain {
  chain_id: string;
  title: string;
  overall_risk: number;
  explanation: string;
  nodes: GraphNode[];
  edges: GraphEdge[];
}

export interface SecurityGatePolicy {
  fail_on_critical: boolean;
  max_allowed_high: number;
  max_allowed_medium: number;
  min_security_score: number;
  block_on_unverified_fixes: boolean;
}

export interface SecurityGateResult {
  status: "passed" | "failed";
  exit_code: number;
  reason: string;
  security_score: number;
  blocking_findings: string[];
}

export interface ScanHistoryItem {
  run_id: string;
  security_score: number;
  total_findings: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  fixed_count: number;
  regression_count: number;
  ci_gate_status: "passed" | "failed";
  scanned_at: string;
}

export interface ExecutiveReport {
  project_id: string;
  run_id: string;
  generated_at: string;
  executive_summary: string;
  security_score: SecurityScore;
  ci_gate: SecurityGateResult;
  critical_findings: VulnerabilityFinding[];
  high_findings: VulnerabilityFinding[];
  medium_findings: VulnerabilityFinding[];
  low_findings: VulnerabilityFinding[];
  attack_chains: AttackChain[];
  remediation_roadmap: {
    step: number;
    finding_id: string;
    title: string;
    severity: string;
    recommended_action: string;
    principle: string;
  }[];
  test_statistics: Record<string, any>;
}
