import re
from typing import Any, Dict, List, Optional
from app.schemas.execution_plan import AttackScenario, AttackScenarioStep
from app.schemas.module2_contract import Module2AttackPlanExport


class Module1AttackPlanAdapter:
    """
    Adapter that transforms Module 1's stable attack plan contract (JSON/dict/model)
    into internal executable AttackScenario objects without tight coupling to Module 1 internals.
    """

    def parse_attack_plan(
        self,
        raw_plan: Module2AttackPlanExport | Dict[str, Any]
    ) -> List[AttackScenario]:
        """
        Parses Module 1 attack plan and converts each attack item into executable AttackScenario.
        """
        if hasattr(raw_plan, "model_dump"):
            plan_dict = raw_plan.model_dump()
        elif isinstance(raw_plan, dict):
            plan_dict = raw_plan
        else:
            raise ValueError(f"Unsupported plan format type: {type(raw_plan)}")

        attack_items = plan_dict.get("attack_plan", [])
        scenarios: List[AttackScenario] = []

        for idx, item in enumerate(attack_items):
            attack_id = item.get("attack_id", f"ATK-{idx+1:03d}")
            category = item.get("type", item.get("category", "General"))
            endpoint = item.get("endpoint", "/")
            method = item.get("method", "GET").upper()
            objective = item.get("objective", f"Execute {attack_id}")
            preconditions = item.get("preconditions", [])
            steps_desc = item.get("steps", [])
            mutations = item.get("mutations", [])
            expected_behavior = item.get("expected_secure_behavior", "403 Forbidden")
            severity = item.get("severity", "medium")
            priority = item.get("priority", "medium")
            reason = item.get("reason", "")

            # Infer expected status code integer from expected_secure_behavior
            expected_status = self._infer_expected_status(expected_behavior, category)

            # Infer required role
            role_required = self._infer_role_required(category, endpoint, steps_desc)

            # Build concrete execution steps
            scenario_steps = self._build_scenario_steps(
                endpoint=endpoint,
                method=method,
                category=category,
                mutations=mutations,
                steps_desc=steps_desc,
                expected_status=expected_status,
                role_required=role_required,
            )

            scenario = AttackScenario(
                scenario_id=f"SCENARIO-{attack_id}",
                attack_id=attack_id,
                category=category,
                endpoint=endpoint,
                method=method,
                objective=objective,
                preconditions=preconditions,
                steps=scenario_steps,
                mutations=mutations,
                expected_secure_behavior=expected_behavior,
                expected_status=expected_status,
                severity=severity,
                priority=priority,
                role_required=role_required,
                is_adaptive=False,
                parent_attack_id=None,
                reason=reason,
            )
            scenarios.append(scenario)

        return scenarios

    def _infer_expected_status(self, expected_behavior: str, category: str) -> int:
        """Extracts status code (401, 403, 400, 404, 405, 422, 429) from description."""
        text = str(expected_behavior).lower()
        if "401" in text or "unauthorized" in text or category.lower() == "authentication":
            return 401
        elif "403" in text or "forbidden" in text or category.lower() in {"authorization", "bola", "role escalation"}:
            return 403
        elif "404" in text or "not found" in text:
            return 404
        elif "405" in text or "method not allowed" in text:
            return 405
        elif "429" in text or "too many requests" in text or "rate-limit" in category.lower():
            return 429
        elif "422" in text or "unprocessable" in text:
            return 422
        elif "400" in text or "bad request" in text:
            return 400
        return 403

    def _infer_role_required(self, category: str, endpoint: str, steps_desc: List[str]) -> str:
        """Determines identity tier (anonymous, user, staff, admin) for the test."""
        cat_lower = category.lower()
        if cat_lower == "authentication" or "unauthenticated" in " ".join(steps_desc).lower():
            return "anonymous"
        elif cat_lower == "role escalation":
            return "user"  # Test if standard user can access admin
        elif "admin" in endpoint.lower() and cat_lower != "role escalation":
            return "admin"
        return "user"

    def _build_scenario_steps(
        self,
        endpoint: str,
        method: str,
        category: str,
        mutations: List[Dict[str, Any]],
        steps_desc: List[str],
        expected_status: int,
        role_required: str,
    ) -> List[AttackScenarioStep]:
        """Constructs concrete HTTP request steps for Bruno."""
        steps: List[AttackScenarioStep] = []
        path = endpoint

        # Extract mutations into path, query, header, and body
        path_vars = re.findall(r"\{([a-zA-Z0-9_]+)\}", path)
        query_params: Dict[str, Any] = {}
        headers: Dict[str, str] = {}
        body: Optional[Any] = None

        if method in {"POST", "PUT", "PATCH"}:
            body = {}

        # Apply mutations
        for mut in mutations:
            p_name = mut.get("parameter_name", "")
            p_loc = mut.get("parameter_location", "query")
            sample = mut.get("payload_sample", "")

            if p_loc == "path" or p_name in path_vars:
                path = path.replace(f"{{{p_name}}}", str(sample))
            elif p_loc == "header":
                if p_name.lower() != "authorization" or sample:
                    headers[p_name] = str(sample)
            elif p_loc == "query":
                query_params[p_name] = sample
            elif p_loc == "body":
                if isinstance(body, dict):
                    body[p_name] = sample
                else:
                    body = sample

        # Replace any remaining unresolved path variables with default test ID
        for var in re.findall(r"\{([a-zA-Z0-9_]+)\}", path):
            default_val = "101" if "id" in var.lower() else "test"
            path = path.replace(f"{{{var}}}", default_val)

        step = AttackScenarioStep(
            step_number=1,
            step_name=f"execute_{category.lower().replace(' ', '_')}_test",
            method=method,
            path=path,
            headers=headers,
            query_params=query_params,
            body=body,
            expected_status=expected_status,
        )
        steps.append(step)
        return steps
