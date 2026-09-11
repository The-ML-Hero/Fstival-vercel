import {
  Project,
  ApiEndpoint,
  ApiResource,
  ApiWorkflow,
  VulnerabilityFinding,
  SecurityScore,
} from "@/types";

const API_BASE_URL = process.env.NEXT_PUBLIC_API_URL || "http://127.0.0.1:8000/api/v1";

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const res = await fetch(`${API_BASE_URL}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      ...(options.headers || {}),
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body?.detail || detail;
    } catch {
      // ignore non-JSON error bodies
    }
    throw new Error(`API request failed (${res.status}): ${detail}`);
  }

  if (res.status === 204) {
    return undefined as unknown as T;
  }

  return res.json() as Promise<T>;
}

export interface AttackPlanResponse {
  project_id: string;
  total_attacks: number;
  categories: Record<string, number>;
  attacks?: unknown[];
}

export interface FixVerificationResponse {
  finding_id: string;
  result: "fixed" | "not_fixed" | "regression" | "inconclusive";
  diff_summary: string;
}

export const apiService = {
  // Projects
  createProject: (name: string, description?: string): Promise<Project> =>
    request<Project>(`/projects`, {
      method: "POST",
      body: JSON.stringify({ name, description }),
    }),

  getProject: (projectId: string): Promise<Project> =>
    request<Project>(`/projects/${projectId}`),

  listProjects: (): Promise<Project[]> => request<Project[]>(`/projects`),

  // Ingestion / Analysis (Module 1)
  importOpenApi: (
    projectId: string,
    specContent: string
  ): Promise<{ title?: string; endpoints_count?: number }> =>
    request(`/projects/${projectId}/import/openapi`, {
      method: "POST",
      body: JSON.stringify({ spec_content: specContent }),
    }),

  analyzeApi: (projectId: string): Promise<{ attack_plan?: unknown[] }> =>
    request(`/projects/${projectId}/analyze`, { method: "POST" }),

  // Discovery (Module 1)
  getEndpoints: (projectId: string): Promise<ApiEndpoint[]> =>
    request<ApiEndpoint[]>(`/projects/${projectId}/endpoints`),

  getResources: (projectId: string): Promise<ApiResource[]> =>
    request<ApiResource[]>(`/projects/${projectId}/resources`),

  getWorkflows: (projectId: string): Promise<ApiWorkflow[]> =>
    request<ApiWorkflow[]>(`/projects/${projectId}/workflows`),

  // Attack plan (Module 1)
  getAttackPlan: (projectId: string): Promise<AttackPlanResponse> =>
    request<AttackPlanResponse>(`/projects/${projectId}/attack-plan`),

  // Findings & score (Module 3)
  getFindings: (runId: string): Promise<VulnerabilityFinding[]> =>
    request<{ findings: VulnerabilityFinding[] }>(`/runs/${runId}/findings`).then(
      (res) => res.findings
    ),

  getFinding: (runId: string, findingId: string): Promise<VulnerabilityFinding> =>
    request<VulnerabilityFinding>(`/runs/${runId}/findings/${findingId}`),

  getSecurityScore: (runId: string): Promise<SecurityScore> =>
    request<SecurityScore>(`/runs/${runId}/score`),

  // Fix verification (Module 3)
  verifyFix: (findingId: string): Promise<FixVerificationResponse> =>
    request<FixVerificationResponse>(`/findings/${findingId}/verify-fix`, {
      method: "POST",
    }),
};

export default apiService;
