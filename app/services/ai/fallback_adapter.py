from typing import Any, Dict, List
from app.schemas.ai_models import (
    AIAnalysisResult,
    AIAttackHypothesis,
    AIAttackMutation,
    AIInferredRole,
    AIResourceCandidate,
    AIWorkflowCandidate,
    AIWorkflowStep,
)
from app.services.ai.base import BaseAIProvider
from app.services.analyzers.mutation_generator import MutationGenerator


class FallbackAIProvider(BaseAIProvider):
    """
    Deterministic rule-based / heuristic AI provider.
    Ensures complete, offline-capable analysis and attack hypothesis generation
    across all 10 security categories without external LLM dependencies.
    """

    def __init__(self):
        self.mutation_gen = MutationGenerator()

    async def analyze_api(self, context: Dict[str, Any]) -> AIAnalysisResult:
        endpoints = context.get("endpoints", [])
        roles_in = context.get("roles", [])
        resources_in = context.get("resources", [])
        workflows_in = context.get("workflows", [])

        sensitive_ops: List[str] = []
        attack_hypotheses: List[AIAttackHypothesis] = []
        attack_counter = 1

        for ep in endpoints:
            path = ep.get("path", "")
            method = ep.get("method", "GET").upper()
            params = ep.get("parameters", [])
            security_req = ep.get("security_required", False)
            endpoint_str = f"{method} {path}"

            # Classify sensitive operations
            path_lower = path.lower()
            is_sensitive = any(
                k in path_lower for k in [
                    "admin", "auth", "login", "password", "user", "order", "pay",
                    "patient", "billing", "token", "delete", "account", "credit"
                ]
            ) or method in {"POST", "PUT", "PATCH", "DELETE"}

            if is_sensitive:
                sensitive_ops.append(endpoint_str)

            # -------------------------------------------------------------
            # Category 1: Authentication
            # -------------------------------------------------------------
            if security_req:
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="Authentication",
                    endpoint=path,
                    method=method,
                    objective=f"Verify if {endpoint_str} correctly rejects unauthenticated requests.",
                    preconditions=["Endpoint requires authentication per specification"],
                    steps=[
                        f"1. Send {method} request to {path} without Authorization header",
                        "2. Send request with expired or invalid Bearer token",
                        "3. Verify response status is 401 Unauthorized"
                    ],
                    expected_secure_behavior="Server returns HTTP 401 Unauthorized with WWW-Authenticate header.",
                    reason="Missing authentication middleware or broken security interceptors could leave endpoint publicly accessible.",
                    severity="high",
                    exploitability=0.90,
                    impact=0.85,
                    confidence=0.92,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="Authorization",
                            parameter_location="header",
                            mutation_type="omitted_auth_header",
                            payload_sample="",
                            rationale="Test request with completely omitted authentication header."
                        ),
                        AIAttackMutation(
                            parameter_name="Authorization",
                            parameter_location="header",
                            mutation_type="invalid_bearer_token",
                            payload_sample="Bearer invalid_token_xyz_123",
                            rationale="Test request with malformed / unsigned token."
                        )
                    ]
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 2: Authorization
            # -------------------------------------------------------------
            if security_req and not any(k in path_lower for k in ["admin", "root"]):
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="Authorization",
                    endpoint=path,
                    method=method,
                    objective=f"Test if a low-privilege user can access restricted operations on {endpoint_str}.",
                    preconditions=["Two user accounts with different permission tiers exist"],
                    steps=[
                        "1. Authenticate as lowest-privilege user",
                        f"2. Issue {method} request to {path}",
                        "3. Inspect if restricted action executes or returns 403 Forbidden"
                    ],
                    expected_secure_behavior="Server returns HTTP 403 Forbidden.",
                    reason="Coarse-grained authentication checks may verify token validity without enforcing granular permission policies.",
                    severity="high",
                    exploitability=0.75,
                    impact=0.80,
                    confidence=0.88,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="X-User-Role",
                            parameter_location="header",
                            mutation_type="unauthorized_role_header",
                            payload_sample="guest",
                            rationale="Simulate lowest privilege user context."
                        )
                    ]
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 3: BOLA / IDOR
            # -------------------------------------------------------------
            has_path_id = any(p.get("location") == "path" for p in params) or "{" in path
            if has_path_id:
                path_param_name = next((p.get("name") for p in params if p.get("location") == "path"), "id")
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="BOLA",
                    endpoint=path,
                    method=method,
                    objective=f"Determine whether an authenticated user can access or manipulate another user's resource on {endpoint_str}.",
                    preconditions=[
                        "Two distinct authenticated accounts exist (User A and User B)",
                        "User A owns a valid resource"
                    ],
                    steps=[
                        "1. Authenticate as User B",
                        f"2. Send {method} request to {path} replacing '{path_param_name}' with User A's resource ID",
                        "3. Check if server returns User A's private data or executes modification"
                    ],
                    expected_secure_behavior="Server verifies resource ownership and returns HTTP 403 Forbidden or 404 Not Found.",
                    reason=f"Endpoint accepts user-controlled object identifier '{path_param_name}' in path without verified ownership validation.",
                    severity="critical",
                    exploitability=0.92,
                    impact=0.95,
                    confidence=0.94,
                    mutations=self.mutation_gen.generate_mutations_for_parameter(path_param_name, "string", "path", "BOLA")
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 4: Role Escalation
            # -------------------------------------------------------------
            if any(k in path_lower for k in ["admin", "manage", "role", "internal", "config"]):
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="Role Escalation",
                    endpoint=path,
                    method=method,
                    objective=f"Determine if a non-admin user can access privileged admin endpoint {endpoint_str}.",
                    preconditions=["Standard non-admin user account is available"],
                    steps=[
                        "1. Authenticate with standard user credentials",
                        f"2. Issue {method} request to {path}",
                        "3. Verify if server enforces strict role-based access control"
                    ],
                    expected_secure_behavior="Server rejects the request with HTTP 403 Forbidden.",
                    reason="Administrative endpoints frequently lack explicit RBAC verification on all HTTP verbs.",
                    severity="critical",
                    exploitability=0.88,
                    impact=0.98,
                    confidence=0.90,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="role",
                            parameter_location="query",
                            mutation_type="parameter_role_override",
                            payload_sample="admin",
                            rationale="Attempt to inject elevated role via query parameter override."
                        )
                    ]
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 5 & 6: Input Validation & Parameter Tampering
            # -------------------------------------------------------------
            for param in params:
                pname = param.get("name", "")
                ptype = param.get("param_type", "string")
                ploc = param.get("location", "query")

                p_mutations = self.mutation_gen.generate_mutations_for_parameter(pname, ptype, ploc)
                if p_mutations:
                    # Parameter Tampering for financial / quantity / roles
                    is_tampering = any(k in pname.lower() for k in ["amount", "price", "role", "total", "cost", "is_admin"])
                    cat = "Parameter Tampering" if is_tampering else "Input Validation"
                    attack_hypotheses.append(AIAttackHypothesis(
                        attack_id=f"ATK-{attack_counter:03d}",
                        category=cat,
                        endpoint=path,
                        method=method,
                        objective=f"Test backend validation constraints and sanitization on parameter '{pname}' at {endpoint_str}.",
                        preconditions=["Endpoint accepts parameter in " + ploc],
                        steps=[
                            f"1. Send {method} request to {path} with mutated values for '{pname}'",
                            "2. Check for unexpected server errors (500), balance tampering, or data corruption"
                        ],
                        expected_secure_behavior="Server rejects invalid values with HTTP 400 or 422 with structured validation error.",
                        reason=f"Parameter '{pname}' controls sensitive business attributes or database queries.",
                        severity="high" if is_tampering else "medium",
                        exploitability=0.80,
                        impact=0.85 if is_tampering else 0.50,
                        confidence=0.86,
                        mutations=p_mutations[:4]
                    ))
                    attack_counter += 1

            # -------------------------------------------------------------
            # Category 7: Rate-Limit Testing
            # -------------------------------------------------------------
            if any(k in path_lower for k in ["login", "auth", "token", "password", "otp", "verify", "export"]):
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="Rate-Limit Testing",
                    endpoint=path,
                    method=method,
                    objective=f"Determine whether {endpoint_str} enforces rate limiting against automated brute force.",
                    preconditions=["Access to endpoint"],
                    steps=[
                        f"1. Send 100 rapid consecutive {method} requests to {path}",
                        "2. Monitor for HTTP 429 Too Many Requests response and Retry-After headers"
                    ],
                    expected_secure_behavior="Server responds with HTTP 429 Too Many Requests after threshold is reached.",
                    reason="Unrestricted authentication/verification endpoints enable brute-force and denial of service.",
                    severity="high",
                    exploitability=0.85,
                    impact=0.70,
                    confidence=0.89,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="X-Forwarded-For",
                            parameter_location="header",
                            mutation_type="ip_rotation_spoofing",
                            payload_sample="192.168.1.{{$randomInt}}",
                            rationale="Test if rate-limiter can be bypassed via client-supplied IP headers."
                        )
                    ]
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 8: HTTP Method Abuse
            # -------------------------------------------------------------
            alt_methods = [m for m in ["DELETE", "PUT", "PATCH", "HEAD"] if m != method]
            if alt_methods:
                test_alt = alt_methods[0]
                attack_hypotheses.append(AIAttackHypothesis(
                    attack_id=f"ATK-{attack_counter:03d}",
                    category="HTTP Method Abuse",
                    endpoint=path,
                    method=test_alt,
                    objective=f"Determine if issuing unadvertised HTTP method {test_alt} on {path} bypasses security controls or leaks info.",
                    preconditions=["Endpoint defined primarily for " + method],
                    steps=[
                        f"1. Dispatch HTTP {test_alt} request to {path}",
                        "2. Observe response code and behavior"
                    ],
                    expected_secure_behavior="Server returns HTTP 405 Method Not Allowed with Allow header.",
                    reason="Web frameworks or reverse proxies may have misconfigured verb-tampering filters.",
                    severity="low",
                    exploitability=0.60,
                    impact=0.40,
                    confidence=0.78,
                    mutations=[
                        AIAttackMutation(
                            parameter_name="X-HTTP-Method-Override",
                            parameter_location="header",
                            mutation_type="method_override_header",
                            payload_sample=test_alt,
                            rationale="Test if verb tunneling overrides routing security."
                        )
                    ]
                ))
                attack_counter += 1

            # -------------------------------------------------------------
            # Category 9: Information Exposure
            # -------------------------------------------------------------
            attack_hypotheses.append(AIAttackHypothesis(
                attack_id=f"ATK-{attack_counter:03d}",
                category="Information Exposure",
                endpoint=path,
                method=method,
                objective=f"Determine whether malformed requests to {endpoint_str} leak stack traces, database metadata, or internal paths.",
                preconditions=["Access to endpoint"],
                steps=[
                    f"1. Send malformed request payload (e.g. invalid JSON, extreme header size) to {path}",
                    "2. Inspect response body and headers for stack traces, server version, or sensitive debugging details"
                ],
                expected_secure_behavior="Server returns generic error response without debugging internals.",
                reason="Improper error handling exposes application architecture and internal implementation secrets.",
                severity="medium",
                exploitability=0.70,
                impact=0.60,
                confidence=0.82,
                mutations=[
                    AIAttackMutation(
                        parameter_name="Content-Type",
                        parameter_location="header",
                        mutation_type="malformed_content_type",
                        payload_sample="application/xml; charset=utf-8",
                        rationale="Force parser exception to trigger verbose stack trace."
                    )
                ]
            ))
            attack_counter += 1

        # -------------------------------------------------------------
        # Category 10: Business Logic (From Workflows)
        # -------------------------------------------------------------
        from app.services.analyzers.business_logic_analyzer import BusinessLogicAnalyzer
        bl_analyzer = BusinessLogicAnalyzer()
        # Convert schema workflows to WorkflowResponse if needed
        bl_hypotheses = bl_analyzer.generate_workflow_attack_hypotheses(
            workflows_in, endpoints, start_counter=attack_counter
        )
        attack_hypotheses.extend(bl_hypotheses)

        # Build output roles, resources, workflows
        ai_roles = [
            AIInferredRole(
                role_name=r.role_name if hasattr(r, "role_name") else r.get("role_name", "user"),
                confidence=r.confidence if hasattr(r, "confidence") else r.get("confidence", 0.8),
                reasoning=r.reasoning if hasattr(r, "reasoning") else r.get("reasoning", "Standard role"),
                evidence=[str(e) for e in (r.evidence if hasattr(r, "evidence") else r.get("evidence", []))],
                associated_endpoints=r.associated_endpoints if hasattr(r, "associated_endpoints") else r.get("associated_endpoints", []),
            )
            for r in roles_in
        ]

        ai_resources = [
            AIResourceCandidate(
                name=res.name if hasattr(res, "name") else res.get("name", "Resource"),
                description=res.description if hasattr(res, "description") else res.get("description"),
                endpoints=res.endpoints if hasattr(res, "endpoints") else res.get("endpoints", []),
                crud_operations=res.crud_operations if hasattr(res, "crud_operations") else res.get("crud_operations", {}),
                relationships=[
                    {
                        "target": rel.target_resource if hasattr(rel, "target_resource") else rel.get("target_resource", ""),
                        "type": rel.relationship_type if hasattr(rel, "relationship_type") else rel.get("relationship_type", ""),
                    }
                    for rel in (res.relationships if hasattr(res, "relationships") else res.get("relationships", []))
                ]
            )
            for res in resources_in
        ]

        ai_workflows = [
            AIWorkflowCandidate(
                workflow_name=wf.workflow_name if hasattr(wf, "workflow_name") else wf.get("workflow_name", "Workflow"),
                description=wf.description if hasattr(wf, "description") else wf.get("description"),
                confidence=wf.confidence if hasattr(wf, "confidence") else wf.get("confidence", 0.85),
                steps=[
                    AIWorkflowStep(
                        step_number=s.step_number if hasattr(s, "step_number") else s.get("step_number", 1),
                        step_name=s.step_name if hasattr(s, "step_name") else s.get("step_name", "step"),
                        endpoint=s.endpoint if hasattr(s, "endpoint") else s.get("endpoint", "/"),
                        method=s.method if hasattr(s, "method") else s.get("method", "GET"),
                        description=s.description if hasattr(s, "description") else s.get("description"),
                        produces_parameters=s.produces_parameters if hasattr(s, "produces_parameters") else s.get("produces_parameters", []),
                        consumes_parameters=s.consumes_parameters if hasattr(s, "consumes_parameters") else s.get("consumes_parameters", []),
                    )
                    for s in (wf.steps if hasattr(wf, "steps") else wf.get("steps", []))
                ]
            )
            for wf in workflows_in
        ]

        summary_text = (
            f"API Guardian static and heuristic AI analysis analyzed {len(endpoints)} endpoints, "
            f"identifying {len(sensitive_ops)} sensitive operations, {len(ai_roles)} role boundaries, "
            f"and generated {len(attack_hypotheses)} prioritized attack hypotheses across 10 security categories."
        )

        return AIAnalysisResult(
            summary=summary_text,
            sensitive_operations=sensitive_ops,
            roles=ai_roles,
            resources=ai_resources,
            workflows=ai_workflows,
            attack_hypotheses=attack_hypotheses,
        )
